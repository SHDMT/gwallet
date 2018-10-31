package addrmgr

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"

	"bytes"
	"encoding/gob"
	"github.com/SHDMT/btcec"
	"github.com/SHDMT/crypto/bliss"
	"github.com/SHDMT/gravity/infrastructure/crypto/hash"
	"github.com/SHDMT/gwallet/infrastructure/config"
	"github.com/SHDMT/gwallet/infrastructure/database"
	"github.com/SHDMT/gwallet/infrastructure/log"
	"github.com/SHDMT/gwallet/platform/walletdb"
)

// const
const (
	SECP256K1 = 0
	BLISS     = 1
	IMPORTED  = 2

	InternalBranch = 1
	ExternalBranch = 0
)

// const
const (
	BlissPubKeyLen = 897
	EcPubKeyLen    = 65

	// is the index at which a hardened key starts.
	HardenedKeyStart   = 0x80000000 // 2^31
	MaxCoinType        = HardenedKeyStart - 1
	MaxAccountNum      = HardenedKeyStart - 2
	ImportedAccountNum = uint32(0)
	DefaultAccountNum  = uint32(1)
)

// Err errors use in this file
var (
	ErrInvalidCoinType        = errors.New("coin type is too high")
	ErrInvalidChild           = errors.New("new child key is invalid")
	ErrDerivePublicFromPublic = errors.New("can't derive bliss publicKey from publicKey ")
	ErrDeriveHardFromPublic   = errors.New("can't derive a hardened key from publicKey")
	ErrUnknownHDKeyID         = errors.New("unknown hd private extended key bytes")
	ErrUnusedAddress          = errors.New(" to many unused address ")
)

var (
	hdPrivateToPubKeyIDs = make(map[[4]byte][]byte)
	zeroBytes            = make([]byte, 32)
)

// ExtendedKey all the information needed to support a hierarchical
// deterministic extended key.
type ExtendedKey struct {
	Version     []byte
	Depth       uint32
	ParentFP    []byte
	ChainCode   []byte
	ChildNumber uint32
	Key         []byte
	IsPrivate   bool
	AlgType     int
}

// AccountInfo all the information needed to support a hierarchical
// deterministic wallet account
type AccountInfo struct {
	PrivKeyEnc []byte
	PubKeyEnc  []byte

	ExternalIndex         uint32
	InternalIndex         uint32
	LastUsedExternalIndex uint32
	LastUsedInternalIndex uint32

	AccountName  string
	AccountType  int
	AccountIndex uint32
	AssetList    []hash.HashType
}

// KeyStore all the information needed to support KeyStore
type KeyStore struct {
	db        database.DB
	cryptoKey *CryptoKey
}

// NewKeyStore create a new keyStore instance
func NewKeyStore(db database.DB, cryptoKey *CryptoKey) *KeyStore {
	return &KeyStore{db: db, cryptoKey: cryptoKey}
}

// GenerateAddressKey Generates a new address under the specified account
func (ks *KeyStore) GenerateAddressKey(acctInfo *AccountInfo,
	internal bool) (uint32, *ExtendedKey, error) {
	var index uint32
	if internal {
		if (acctInfo.InternalIndex+1)-acctInfo.LastUsedInternalIndex > ScanLength {
			return index, nil, ErrUnusedAddress
		}
		index = acctInfo.InternalIndex + 1

	} else {
		if (acctInfo.ExternalIndex+1)-acctInfo.LastUsedExternalIndex > ScanLength {
			return index, nil, ErrUnusedAddress
		}
		index = acctInfo.ExternalIndex + 1

	}
	if acctInfo.AccountType == BLISS {
		if bytes.Equal(ks.cryptoKey.Bytes(), zeroBytes) || ks.cryptoKey == nil {
			return index, nil, errors.New(" wallet is locked ")
		}
		acctPrivKeyBytes, err := ks.cryptoKey.Decrypt(acctInfo.PrivKeyEnc)
		if err != nil {
			return index, nil, errors.New(" can't decrypt account privateKey ")
		}
		acctPrivKey := new(ExtendedKey)
		err = acctPrivKey.UnMarshal(acctPrivKeyBytes)
		if err != nil {
			return index, nil,
				errors.New(" can't unmarshal account privateKey ")
		}
		addressPrivKey, err := acctPrivKey.DerivPrivKey(ExternalBranch, index, BLISS)
		if err != nil {
			return index, nil, err
		}
		addressPubKey, err := addressPrivKey.PublicKey()
		if err != nil {
			return index, nil, err
		}
		err = dbPutKeyPair(ks.db, addressPrivKey, addressPubKey)
		if err != nil {
			return index, nil, errors.New(" save new address keyPair failed")
		}
		return index, addressPubKey, nil
	}
	acctPubKeyBytes, err := ks.cryptoKey.Decrypt(acctInfo.PubKeyEnc)
	if err != nil {
		return index, nil, errors.New("can't decrypt account publicKey ")
	}
	acctPubKey := new(ExtendedKey)
	err = acctPubKey.UnMarshal(acctPubKeyBytes)
	if err != nil {
		return index, nil, errors.New("can't unmarshal account publicKey ")
	}
	addrPubKey, err := deriveNextAddress(acctPubKey, index, internal, SECP256K1)
	if err != nil {
		return index, nil, err
	}
	return index, addrPubKey, nil
}

func deriveNextAddress(acctKey *ExtendedKey, index uint32, internal bool, acctType int) (*ExtendedKey, error) {

	var branchKey *ExtendedKey
	var err error
	if internal {
		branchKey, err = acctKey.DeriveChildKey(InternalBranch, acctType)
		if err != nil {
			return nil, err
		}
	} else {
		branchKey, err = acctKey.DeriveChildKey(ExternalBranch, acctType)
		if err != nil {
			return nil, err
		}
	}

	addressKey, err := branchKey.DeriveChildKey(index, acctType)
	if err != nil {
		return nil, err
	}
	return addressKey, nil
}

// DeriveAccountKey derive account key with account index and algorithm type
func (k *ExtendedKey) DeriveAccountKey(account uint32, accType int) (*ExtendedKey, error) {
	if account > MaxAccountNum {
		log.Error(" account number may invalid  ")
		return nil, errors.New("account number may invalid")
	}

	acctKey, err := k.DeriveChildKey(account, accType)
	if err != nil {
		return nil, errors.New("can't derive child from cointype key")
	}
	return acctKey, nil
}

// DeriveChildKey derive child key with child index and algorithm type
func (k *ExtendedKey) DeriveChildKey(i uint32, algType int) (*ExtendedKey, error) {
	if k == nil {
		return nil, errors.New("your extendedKey is nil, can't derive child key")
	}
	switch algType {
	case SECP256K1:
		return k.Child(i, false, SECP256K1)

	case BLISS:
		if !k.IsPrivate {
			return nil, ErrDerivePublicFromPublic
		}
		return k.Child(i, true, BLISS)

	default:
		return nil, nil
	}
}

// Child derive child key with child index and algorithm type
func (k *ExtendedKey) Child(i uint32, isPriv bool, acctype int) (*ExtendedKey, error) {
	var childKey []byte
	var isPrivate = isPriv
	var err error
	childChainCode := make([]byte, 32)
	if k == nil {
		return nil, nil
	}
	if k.AlgType != SECP256K1 && !k.IsPrivate {
		return nil, ErrDerivePublicFromPublic
	}

	switch acctype {
	case BLISS:
		childKey, childChainCode, err = k.blissChild(i)
		if err != nil {
			log.Error(" derive child key failed for Bliss")
			return nil, err
		}
	default:
		childKey, childChainCode, isPrivate, err = k.ecChild(i)
		if err != nil {
			log.Error(" derive child key failed for Secp256k1")
			return nil, err
		}
	}

	parentFP := hash.Sum160(k.PublicKeyBytes())[:4]

	return &ExtendedKey{
		Version:     k.Version,
		Depth:       k.Depth + 1,
		ParentFP:    parentFP,
		ChainCode:   childChainCode,
		ChildNumber: i,
		Key:         childKey,
		IsPrivate:   isPrivate,
		AlgType:     acctype,
	}, nil
}

func (k *ExtendedKey) blissChild(i uint32) ([]byte, []byte, error) {
	data := make([]byte, BlissPubKeyLen+4)
	copy(data, k.PublicKeyBytes())
	binary.BigEndian.PutUint32(data[BlissPubKeyLen:], i)
	hmac512 := hmac.New(sha512.New, k.ChainCode)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)
	il := ilr[:len(ilr)/2]
	childChainCode := ilr[len(ilr)/2:]
	entropyRand := hash.Sum512(il)
	blissCipher := bliss.NewCipherSuite()

	entropy := new(bytes.Buffer)
	entropy.Write(entropyRand[:])

	privKey, err := blissCipher.GenerateKey(entropy)
	if err != nil && strings.Contains(err.Error(), "invertible polynomial") {
		return nil, nil, ErrInvalidChild
	}
	if err != nil {
		return nil, nil, err
	}
	childKey, err := privKey.MarshalP()

	return childKey, childChainCode, nil
}

func (k *ExtendedKey) ecChild(i uint32) ([]byte, []byte, bool, error) {

	var isPrivate = false
	var childChainCode = make([]byte, 32)
	var childKey []byte

	isChildHardened := i >= HardenedKeyStart
	k.AlgType = SECP256K1
	if !k.IsPrivate && isChildHardened {
		return nil, nil, false, ErrDeriveHardFromPublic
	}

	keyLen := EcPubKeyLen
	data := make([]byte, keyLen+4)
	if isChildHardened {
		copy(data[1:], k.Key)
	} else {
		copy(data, k.PublicKeyBytes())
	}
	binary.BigEndian.PutUint32(data[keyLen:], i)

	hmac512 := hmac.New(sha512.New, k.ChainCode)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)
	il := ilr[:len(ilr)/2]
	copy(childChainCode, ilr[len(ilr)/2:])

	ilNum := new(big.Int).SetBytes(il)
	if ilNum.Cmp(btcec.S256().N) >= 0 || ilNum.Sign() == 0 {
		return nil, nil, false, ErrInvalidChild
	}

	if k.IsPrivate {
		keyNum := new(big.Int).SetBytes(k.Key)
		ilNum.Add(ilNum, keyNum)
		ilNum.Mod(ilNum, btcec.S256().N)
		childKey = ilNum.Bytes()
		isPrivate = true
	} else {
		ilx, ily := btcec.S256().ScalarBaseMult(il)
		if ilx.Sign() == 0 || ily.Sign() == 0 {
			return nil, nil, isPrivate, ErrInvalidChild
		}
		pubKey, err := btcec.ParsePubKey(k.Key, btcec.S256())
		if err != nil {
			return nil, nil, isPrivate, err
		}

		childX, childY := btcec.S256().Add(ilx, ily, pubKey.X, pubKey.Y)

		publicKey := new(btcec.PublicKey)
		publicKey.Curve = btcec.S256()
		publicKey.X = childX
		publicKey.Y = childY
		childKey = publicKey.SerializeUncompressed()
	}

	return childKey, childChainCode, isPrivate, nil
}

// DerivPrivKeys Generate all address keys with indexes between start and end, in designated branch
func (k *ExtendedKey) DerivPrivKeys(branch uint32, startIndex uint32, endIndex uint32, acctType int) ([]*ExtendedKey, error) {

	privKeys := make([]*ExtendedKey, 0)

	for i := startIndex; i <= endIndex; i++ {
		privKey, err := k.DerivPrivKey(branch, i, acctType)
		if err != nil {
			log.Warn(" can't derive private key")
			continue
		}
		privKeys = append(privKeys, privKey)
	}
	return privKeys, nil
}

// DerivPrivKey  Generate the corresponding branch key and address key, according to the designated branch index and address index
func (k *ExtendedKey) DerivPrivKey(branch uint32, index uint32,
	algType int) (*ExtendedKey, error) {

	branchKey, err := k.DeriveChildKey(branch, algType)
	if err != nil {
		return nil, err
	}

	privKey, err := branchKey.DeriveChildKey(index, algType)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

// PublicKey get public key from ExtendedKey
func (k *ExtendedKey) PublicKey() (*ExtendedKey, error) {
	if k == nil {
		return nil, errors.New("extended key is nil")
	}
	if !k.IsPrivate {
		return k, nil
	}

	// Get the associated public extended key version bytes.
	version, err := HDPrivateKeyToPublicKeyID(k.Version)
	if err != nil {
		return nil, err
	}

	return &ExtendedKey{
		Version:     version,
		Depth:       k.Depth,
		ParentFP:    k.ParentFP,
		ChainCode:   k.ChainCode,
		ChildNumber: k.ChildNumber,
		Key:         k.PublicKeyBytes(),
		IsPrivate:   false,
		AlgType:     k.AlgType,
	}, nil
}

// PublicKeyBytes get public key bytes from ExtendedKey
func (k *ExtendedKey) PublicKeyBytes() []byte {
	if k == nil {
		return nil
	}
	if !k.IsPrivate {
		return k.Key
	}

	var pubKey []byte
	if k.AlgType == BLISS {
		blissCipher := bliss.NewCipherSuite()
		privKey, err := blissCipher.UnmarshalPrivateKey(k.Key)
		if err != nil {
			return nil
		}
		pubKey, err = privKey.Public().MarshalP()
		if err != nil {
			log.Error("marshal public key failed")
		}
	} else {
		pkx, pky := btcec.S256().ScalarBaseMult(k.Key)
		publicKey := new(btcec.PublicKey)
		publicKey.Curve = btcec.S256()
		publicKey.X = pkx
		publicKey.Y = pky

		pubKey = publicKey.SerializeUncompressed()
	}
	return pubKey
}

// Marshal ExtendedKey serialize
func (k *ExtendedKey) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := gob.NewEncoder(buf).Encode(k)
	return buf.Bytes(), err
}

// UnMarshal ExtendedKey deserialize
func (k *ExtendedKey) UnMarshal(key []byte) error {
	buf := bytes.NewBuffer(key)
	err := gob.NewDecoder(buf).Decode(k)
	if err != nil {
		return err
	}
	return nil
}

// Zero clear ExtendedKey data
func (k *ExtendedKey) Zero() {
	zero(k.Key)
	zero(k.ChainCode)
	zero(k.ParentFP)
	k.Version = nil
	k.Key = nil
	k.Depth = 0
	k.ChildNumber = 0
	k.AlgType = 0
	k.IsPrivate = false
}

func zero(b []byte) {
	lenB := len(b)
	for i := 0; i < lenB; i++ {
		b[i] = 0
	}
}

// HDPrivateKeyToPublicKeyID get HDPublicKeyID from HDPrivateKeyID
func HDPrivateKeyToPublicKeyID(id []byte) ([]byte, error) {
	if len(id) != 4 {
		return nil, ErrUnknownHDKeyID
	}

	var key [4]byte
	copy(key[:], id)
	pubBytes, ok := hdPrivateToPubKeyIDs[key]
	if !ok {
		return nil, ErrUnknownHDKeyID
	}

	return pubBytes, nil
}

// EncodeAccountInfo accountInfo serialize
func (acctInfo *AccountInfo) EncodeAccountInfo() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := gob.NewEncoder(buf).Encode(acctInfo)
	return buf.Bytes(), err
}

// DecodeAccountInfo accountInfo deserialize
func (acctInfo *AccountInfo) DecodeAccountInfo(acct []byte) error {
	buf := bytes.NewBuffer(acct)
	err := gob.NewDecoder(buf).Decode(acctInfo)
	if err != nil {
		return err
	}

	return nil
}

//  dbPutKeyPair put address keyPair to database
func dbPutKeyPair(db database.DB, key *ExtendedKey, pubkey *ExtendedKey) error {
	err := db.Update(func(tx database.Tx) error {

		privbytes, err := key.Marshal()
		if err != nil {
			log.Error(" private key encode err : ", err)
			return err
		}

		err = walletdb.DbPutKeyPairs(tx, pubkey.Key, privbytes)
		if err != nil {
			log.Error(" put keypair to database err : ", err)
			return err
		}
		return nil
	})
	if err != nil {
		log.Error(" put keypair to database failed : ", err)
		return err
	}

	return nil
}

func init() {
	hdPrivateToPubKeyIDs[config.Parameters.HDPrivateKeyID] = config.Parameters.HDPublicKeyID[:]
}
