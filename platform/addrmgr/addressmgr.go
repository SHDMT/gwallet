package addrmgr

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"github.com/SHDMT/crypto/secp256k1"
	"github.com/SHDMT/gravity/infrastructure/crypto/hash"
	"github.com/SHDMT/gravity/platform/consensus/genesis"
	"github.com/SHDMT/gravity/platform/messagevalidator"
	"github.com/SHDMT/gwallet/infrastructure/config"
	"github.com/SHDMT/gwallet/infrastructure/database"
	e "github.com/SHDMT/gwallet/infrastructure/errors"
	"github.com/SHDMT/gwallet/infrastructure/log"
	"github.com/SHDMT/gwallet/platform/grpc/walletrpc"
	"github.com/SHDMT/gwallet/platform/walletdb"
	"github.com/pkg/errors"
)

// ScanLength Maximum number of consecutive unused addresses supported
const (
	ScanLength        = 20
	maxEmptyAccounts = 100
)

var (
	// ErrInvalidAccountName account name is invalid
	ErrInvalidAccountName = errors.New("Account name is reserved by gRPC server")
	// ErrAccountAccountEmpty account name string is empty
	ErrAccountAccountEmpty = errors.New("accounts may not be named the empty string")
	// ErrNoTransactions last 100 accounts have no transaction history
	ErrNoTransactions = errors.New("last 100 accounts have no transaction history")
	// ErrSaveAddressFailed  can't save address to database
	ErrSaveAddressFailed = errors.New("db put address failed")
	// ErrSavePubicKeyFailed can't save address't public key
	ErrSavePubicKeyFailed = errors.New("db put address public key failed")
	// ErrGenerateAddressFailed  can't generate new address
	ErrGenerateAddressFailed = errors.New("generate address failed")
)

// Address all the information needed to support a hierarchical
// deterministic wallet address
type Address struct {
	Account  uint32
	Address  []byte
	Internal bool
	Imported bool
	Index    uint32
	PubKey   []byte
}

// AddressManager all the information needed to support addressManager
type AddressManager struct {
	keyStore *KeyStore
	db       database.DB
}

// NewAddressManager create address manager instance
func NewAddressManager(keystrore *KeyStore, db database.DB) *AddressManager {

	return &AddressManager{
		keyStore: keystrore,
		db:       db,
	}
}

// NewAddress Create an external or internal address under the designated account.
func NewAddress(account uint32, address []byte, internal bool, imported bool,
	index uint32, pubkey []byte) *Address {

	return &Address{Account: account, Address: address, Internal: internal,
		Imported: imported, Index: index, PubKey: pubkey}
}

// SetDb set wallet database to addressManager instance
func (am *AddressManager) SetDb(db database.DB) {
	am.db = db
}

// SetKeyStore set wallet keyStore to addressManager instance
func (am *AddressManager) SetKeyStore(keystore *KeyStore) {
	am.keyStore = keystore
}

// Hash160 calculate a digest use hash160
func (addr *Address) Hash160() ([]byte, error) {

	addrBytes, err := EncodeAddress(addr)
	if err != nil {
		return nil, fmt.Errorf("Error of encodeAddress has happend : %v ", err)
	}

	addHash := hash.Sum160(addrBytes)
	return addHash, nil
}

// NewAddress create a new address instance use specified args
func (am *AddressManager) NewAddress(accountName string, internal bool) (*Address, error) {
	var accountIndex uint32
	var err error
	if accountName == "" {
		accountIndex = DefaultAccountNum
	} else {
		accountIndex, err = dbFetchAccountByName(am.db, accountName)
		if err != nil {
			return nil, errors.New("can't find the specified account")
		}
	}
	return am.CreateNewAddress(accountIndex, internal)
}

// CreateNewAddress Create an external or internal address under the designated account.
func (am *AddressManager) CreateNewAddress(accountIndex uint32, internal bool) (*Address, error) {
	accountInfo, err := dbFetchAccountInfo(am.db, accountIndex)
	if err != nil {
		return nil, err
	}
	index, pubKey, err := am.keyStore.GenerateAddressKey(accountInfo,
		internal)
	if err != nil {
		log.Error("generate keyPair failed : ", err)
		return nil, err
	}
	if internal {
		accountInfo.InternalIndex = index
		accountInfo.LastUsedInternalIndex = index
	} else {
		accountInfo.ExternalIndex = index
	}

	acctBytes, err := accountInfo.EncodeAccountInfo()
	if err != nil {
		log.Error(" marshal account info to database failed , ", err)
		return nil, err
	}
	err = saveAccountInfo(am.db, accountIndex, acctBytes)
	if err != nil {
		return nil, err
	}
	return GetAddressByPubKey(am.db, accountIndex, internal, false, index, pubKey)
}

// GetAddressByPubKey Generate a wallet address based on the designated account information and public key
func GetAddressByPubKey(db database.DB, accountIndex uint32,
	internal bool, imported bool, index uint32, pubKey *ExtendedKey) (*Address,
	error) {
	pubkeybytes, err := pubKey.Marshal()
	addrHash := hash.Sum256(pubKey.Key)
	address := NewAddress(accountIndex, addrHash, internal, imported, index,
		pubKey.PublicKeyBytes())
	err = dbPutAddress(db, address)
	if err != nil {
		log.Error(ErrSaveAddressFailed, err)
		return nil, err
	}
	err = dbPutAddrToPubKey(db, addrHash, pubkeybytes)
	if err != nil {
		log.Error(ErrSavePubicKeyFailed, err)
		return nil, err
	}

	return address, nil
}

// GetAddressByPubBytes Generate a wallet address based on the designated account information and public key
func GetAddressByPubBytes(db database.DB, accountIndex uint32, internal bool,
	imported bool,index uint32, pubKey []byte) (*Address,
	error) {

	addrHash := hash.Sum256(pubKey)
	address := NewAddress(accountIndex, addrHash, internal, imported, index,
		pubKey)
	err := dbPutAddress(db, address)
	if err != nil {
		log.Error(ErrSaveAddressFailed, err)
		return nil, err
	}
	err = dbPutAddrToPubKey(db, addrHash, pubKey)
	if err != nil {
		log.Error(ErrSavePubicKeyFailed, err)
		return  nil, err
	}
	return address, nil
}

// EncodeAddress address serialize
func EncodeAddress(addr *Address) ([]byte, error) {

	buf := new(bytes.Buffer)
	err := gob.NewEncoder(buf).Encode(addr)

	return buf.Bytes(), err
}

// DecodeAddress address deserialize
func DecodeAddress(addressBytes []byte) (*Address,
	error) {

	buf := bytes.NewBuffer(addressBytes)

	addr := new(Address)
	err := gob.NewDecoder(buf).Decode(addr)

	return addr, err
}

// ValidateAddress Check if input address is valid and if it is the address of current wallet
func (am *AddressManager) ValidateAddress(address string) *walletrpc.ValidateAddressResponse {

	result := &walletrpc.ValidateAddressResponse{}
	result.Address = address

	addrBytes, err := base64.StdEncoding.DecodeString(address)
	if err != nil {
		result.IsValid = false
		return result
	}
	result.IsValid = true

	addr, err := DBFetchAddress(am.db, addrBytes)
	if err != nil {
		return result
	}
	result.IsMine = true
	result.PubKey = hex.EncodeToString(addr.PubKey)

	account := addr.Account
	acctName, err := dbFetchAccountName(am.db, account)
	if err != nil {
		return result
	}
	result.Account = acctName
	return result
}

// GetImportedAddress create wallet address from imported private key
func (am *AddressManager) GetImportedAddress(wifString string) (*Address, error) {

	var wif WIF
	err := wif.ParseWIF(wifString)
	if err != nil {
		log.Error("can't parse input wif key")
		return nil, err
	}
	if wif.netType != config.Parameters.NetType {
		log.Warn("your wif netType is missMatch.")
		return nil, errors.New(" privateKey netType missMatch")
	}

	privKey := new(secp256k1.PrivateKey)
	err = privKey.UnmarshalP(wif.PrivKey)
	if err != nil {
		log.Error(" can't unmarshal privateKey.")
		return nil, err
	}

	pubKey := privKey.Public()

	pubKeyBytes, err := pubKey.MarshalP()
	if err != nil {
		log.Error(" publicKey marshal failed.")
		return nil, err
	}

	address, err := GetAddressByPubBytes(am.db, ImportedAccountNum, false, true,0, pubKeyBytes)
	if err != nil {
		log.Error(" get publicKey failed: ", err)
		return nil, err
	}
	return address, nil
}

// RecoverAllUsedAddress Restore all used addresses under the designated account
func (am *AddressManager) RecoverAllUsedAddress(acctKey *ExtendedKey, account uint32, branch uint32, acctType int, lastUsedAddress uint32) error {

	for i := uint32(0); i <= lastUsedAddress; i++ {
		addrPriv, err := acctKey.DerivPrivKey(branch, i, acctType)
		if err != nil {
			log.Warn(" can't derive private key of index : ", i)
			continue
		}

		pubKey, err := addrPriv.PublicKey()
		if err != nil {
			log.Warn("can't get publickey ")
			continue
		}

		err = dbPutKeyPair(am.db, addrPriv, pubKey)
		if err != nil {
			log.Warnf(" save new address keypair failed")
			continue
		}

		addrHash := hash.Sum256(pubKey.Key)
		var addr *Address
		if branch == ExternalBranch {
			addr = NewAddress(account, addrHash, false, false, i,
				pubKey.PublicKeyBytes())
		} else {
			addr = NewAddress(account, addrHash, true, false, i,
				pubKey.PublicKeyBytes())
		}
		err = dbPutAddress(am.db, addr)
		if err != nil {
			log.Error(ErrSaveAddressFailed, err)
			return err
		}
		pubKeyBytes, err := pubKey.Marshal()
		if err != nil {
			continue
		}
		err = dbPutAddrToPubKey(am.db, addrHash, pubKeyBytes)
		if err != nil {
			log.Error(ErrSavePubicKeyFailed, err)
			return err
		}
	}
	return nil
}

// CreateNewAccount create a new wallet account with specified account name and algorithm
func (am *AddressManager) CreateNewAccount(cryptoKey *CryptoKey,
	accountName string, acctType int) (uint32, *Address, error) {
	err := ValidateAccountName(accountName)
	if err != nil {
		return 0, nil, err
	}
	account, address, err := am.nextAccount(cryptoKey, accountName, acctType)
	if err != nil {
		return 0, nil, err
	}

	return account, address, nil
}

// IsOfficial check  if the current wallet is an official wallet
func (am *AddressManager)IsOfficial() (bool){
	var result bool
	for _, address := range messagevalidator.OfficialAddresses {
		var err error
		result, err = dbHasAddress(am.db, address)
		if err != nil {
			continue
		}
		result = true
		break
	}

	return result
}

// ValidateAccountName check if the account name is valid
func ValidateAccountName(name string) error {
	if name == "" {
		return ErrAccountAccountEmpty
	}

	if name == "*" {
		return ErrInvalidAccountName
	}

	if isReservedAccountName(name) {
		return errors.New("reserved account name")
	}
	return nil
}

// isReservedAccountName check if the account name is reserved
func isReservedAccountName(name string) bool {
	if "default" == name || "imported" == name{
		return true
	}
	return false

}

func (am *AddressManager) nextAccount(cryptoKey *CryptoKey,
	name string, acctType int) (uint32, *Address, error) {

	var account uint32
	var lastUsedAccount uint32

	err := am.db.Update(func(tx database.Tx) error {
		errString := "account with the same name already exists"
		accountExistErr := e.NewWalletError(e.ErrHasExist, errString, nil)
		sameName := walletdb.DbHasAccount(tx, []byte(name))
		if sameName {
			return accountExistErr
		}
		var err error
		account, err = walletdb.DbFetchLastAccount(tx)
		if err != nil {
			return err
		}

		lastUsedAccount, err = walletdb.DbFetchLastUsedAccount(tx)
		if err != nil {
			return err
		}
		account++

		return nil
	})

	if err != nil {
		errString := "account with the same name already exists or failed to" +
			" query lastAccount or lastUsedAccount"
		accountExistErr := e.NewWalletError(e.ErrHasExist, errString, nil)
		return 0, nil, accountExistErr
	}
	if account-lastUsedAccount > maxEmptyAccounts {
		return 0, nil, ErrNoTransactions
	}
	address, err := am.newAccount(cryptoKey, account, name, acctType)
	if err != nil {
		return 0, nil, err
	}

	return account, address, err
}

func (am *AddressManager) newAccount(cryptoKey *CryptoKey, account uint32,
	name string, acctType int) (*Address, error) {

	extendedKey := new(ExtendedKey)
	var coinTypeKey []byte
	var err error
	//数据库查询出coinTypeKey
	err = am.db.View(func(tx database.Tx) error {
		coinTypeKey, err = walletdb.DbFetchCoinTypeKey(tx, []byte("coinPriv"))
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	//解密
	coinTypeKeyBytes, err := cryptoKey.Decrypt(coinTypeKey)
	errString := "CryptoKey decrypt failed!"
	accountErr := e.NewWalletError(e.ErrDecrypt, errString, err)
	if err != nil {
		return nil, accountErr
	}

	//反序列化
	err = extendedKey.UnMarshal(coinTypeKeyBytes)
	errString = "ExtendedKey unmarshal failed!"
	unmarshalErr := e.NewWalletError(e.ErrUnmarshal, errString, err)
	if err != nil {
		return nil, unmarshalErr
	}

	//导出私钥
	accountPrivKey, err := extendedKey.DeriveAccountKey(account, acctType)
	errString = "Derive privateKey failed!"
	if err != nil {
		return nil, e.NewWalletError(e.ErrUnmarshal, errString, err)
	}
	//导出公钥
	accountPubKey, err := accountPrivKey.PublicKey()
	errString = "Derive publicKey failed!"
	if err != nil {
		return nil, e.NewWalletError(e.ErrUnmarshal, errString, err)
	}
	privatekeyBytes, err := accountPrivKey.Marshal()
	if err != nil {
		errString = "marshal account privatekey failed!"
		return nil, e.NewWalletError(e.ErrMarshal, errString, err)
	}
	//加密公私钥
	privateKey, err := cryptoKey.Encrypt(privatekeyBytes)
	errString = "Encrypt privateKey failed!"
	if err != nil {
		return nil, e.NewWalletError(e.ErrEncrypt, errString, err)
	}
	log.Debug(" account Private key enc --:%x \n", privateKey)
	publickeyBytes, err := accountPubKey.Marshal()
	if err != nil {
		errString = "marshal account publickey failed!"
		return nil, e.NewWalletError(e.ErrMarshal, errString, err)
	}
	publicKey, err := cryptoKey.Encrypt(publickeyBytes)
	errString = "Encrypt publicKey failed!"
	if err != nil {
		return nil, e.NewWalletError(e.ErrEncrypt, errString, err)
	}
	//组装accountInfo，并序列化
	assetList := make([]hash.HashType, 0)
	assetList = append(assetList, genesis.GenesisAsset)
	accountInfo := &AccountInfo{
		PrivKeyEnc: privateKey,
		PubKeyEnc:  publicKey,

		ExternalIndex:         0,
		InternalIndex:         0,
		LastUsedExternalIndex: 0,
		LastUsedInternalIndex: 0,

		AccountName:  name,
		AccountIndex: account,
		AccountType:  acctType,
		AssetList:    assetList,
	}
	accountInfoBytes, err := accountInfo.EncodeAccountInfo()
	errString = "AccountInfo marshal failed!"
	if err != nil {
		return nil, e.NewWalletError(e.ErrMarshal, errString, err)
	}
	//生成默认地址
	//accountPrivKey.DerivPrivKey(ExternalBranch,0,acctType)
	externalKey, err := accountPrivKey.DeriveChildKey(0, acctType)
	if err != nil {
		log.Warn(ErrGenerateAddressFailed)
		return nil, nil
	}
	addrPrivKey, err := externalKey.DeriveChildKey(0, acctType)
	if err != nil {
		log.Warn(ErrGenerateAddressFailed)
		return nil, nil
	}
	log.Debugf("account privatekey is : %x \n", addrPrivKey.Key)
	addrPubKey, err := addrPrivKey.PublicKey()
	if err != nil {
		log.Warn(ErrGenerateAddressFailed)
		return nil, nil
	}
	addrPubKeyBytes, err := addrPubKey.Marshal()
	addrHash := hash.Sum256(addrPubKey.Key)
	// 创建Address 对象
	address := NewAddress(account, addrHash, false, false, uint32(0),
		addrPubKey.PublicKeyBytes())
	encodeAddr, err := EncodeAddress(address)
	if err != nil {
		return nil, err
	}
	err = dbPutKeyPair(am.db, addrPrivKey, addrPubKey)
	if err != nil {
		log.Warn(" new address save failed : ", err)
		return nil, err
	}

	//存入数据库
	errList := make([]error, 6)
	err = am.db.Update(func(tx database.Tx) error {
		errList[0] = walletdb.DbPutLastAccount(tx, account)
		errList[1] = walletdb.DbPutAccountInfo(tx, account, accountInfoBytes)
		errList[2] = walletdb.DbPutAccountName(tx, account, []byte(name))
		errList[3] = walletdb.DbPutAddress(tx, addrHash, encodeAddr)
		errList[4] = walletdb.DbPutAddrPub(tx, addrHash, addrPubKeyBytes)
		errList[5] = walletdb.DbPutAccount(tx, []byte(name), account)

		for _, err := range errList {
			errString = "Put DB failed!"
			if err != nil {
				return e.NewWalletError(e.ErrPutDB, errString, err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return address, err
}

// dbPutAddress put address and  address public key to database,
// key is address public key , value is address
func dbPutAddress(db database.DB, address *Address) error {

	err := db.Update(func(tx database.Tx) error {

		key := address.Address

		encodeAddr, err := EncodeAddress(address)
		if err != nil {
			return err
		}

		return walletdb.DbPutAddress(tx, key, encodeAddr)
	})
	return err
}

// dbPutAddrToPubKey put address and  address public key hash to database,
// key is address public key hash , value is address
func dbPutAddrToPubKey(db database.DB, addrHash hash.HashType, pubkey []byte) error {

	err := db.Update(func(tx database.Tx) error {
		err := walletdb.DbPutAddrPub(tx, addrHash, pubkey)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

// DBFetchAddress fetch address through address public key hash
func DBFetchAddress(db database.DB, addrHash []byte) (*Address, error) {

	var addressbyts []byte
	err := db.View(func(tx database.Tx) error {
		var err error
		addressbyts, err = walletdb.DbFetchAddress(tx, addrHash)

		return err
	})
	if err != nil {
		return nil, err
	}
	address, err := DecodeAddress(addressbyts)
	if err != nil {
		return nil, err
	}
	return address, nil
}

// dbFetchAccountName fetch account name through the account index
func dbFetchAccountName(db database.DB, index uint32) (string, error) {

	var acctName []byte
	err := db.View(func(tx database.Tx) error {
		var err error
		acctName, err = walletdb.DbFetchAccountName(tx, index)
		return err
	})
	if err != nil {
		return "", err
	}
	return string(acctName), nil
}

// dbFetchAccountByName fetch account index through the account name
func dbFetchAccountByName(db database.DB, name string) (uint32, error) {

	var index []byte
	err := db.View(func(tx database.Tx) error {
		var err error
		index, err = walletdb.DbFetchAccount(tx, []byte(name))
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	account := uint32(binary.BigEndian.Uint32(index))
	return account, nil
}

// dbFetchAccountInfo fetch account information from database
func dbFetchAccountInfo(db database.DB, index uint32) (*AccountInfo, error) {

	var accountBytes []byte
	err := db.View(func(tx database.Tx) error {
		var err error
		accountBytes, err = walletdb.DbFetchAccountInfo(tx, index)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	acctInfo := new(AccountInfo)
	err = acctInfo.DecodeAccountInfo(accountBytes)
	if err != nil {
		return nil, err
	}
	return acctInfo, nil
}

// dbHasAddress Check if the address exists in the database
func dbHasAddress(db database.DB, addr hash.HashType) (bool, error){

	err := db.View(func(tx database.Tx) error {
		_, err := walletdb.DbFetchAddress(tx, addr)
		return err
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

// saveAccountInfo put account information to database
func saveAccountInfo(db database.DB, index uint32, value []byte) error {
	err := db.Update(func(tx database.Tx) error {
		err := walletdb.DbPutAccountInfo(tx, index, value)
		return err
	})
	return err
}
