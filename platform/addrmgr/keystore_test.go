package addrmgr

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/SHDMT/btcec"
	"github.com/SHDMT/gravity/infrastructure/crypto/asymmetric/ec/secp256k1"
	"github.com/SHDMT/gravity/infrastructure/crypto/hash"
	"github.com/SHDMT/gravity/platform/consensus/genesis"
	"github.com/SHDMT/gwallet/infrastructure/config"
	"github.com/SHDMT/gwallet/infrastructure/database"
	"github.com/SHDMT/gwallet/infrastructure/log"
	"github.com/SHDMT/gwallet/infrastructure/utils"
	"github.com/SHDMT/gwallet/platform/walletdb"
	"math/big"
	"os"
	"testing"
)

func TestNewKeyStore(t *testing.T) {
	log.Init(config.Parameters.MaxLogSize, config.Parameters.LogLevel, config.DefaultLogDir+"/", log.Stdout)

	dbPath := "./~temp/TestNewKeyStore/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	DeCompress(testdata, dbPath)
	db, err := openDb(dbPath)
	if err != nil {
		t.Error(" open database failed : ", err)
		return
	}
	defer func() {
		db.Close()
		os.RemoveAll(config.Parameters.DataDir)
	}()

	keystore := NewKeyStore(db, nil)

	t.Logf(" keystore created : %+v \n", keystore)
}

func TestGenerateNewKeyPair(t *testing.T) {
	log.Init(config.Parameters.MaxLogSize, config.Parameters.LogLevel, config.DefaultLogDir+"/", log.Stdout)

	cipherSuite := secp256k1.NewCipherSuite()
	privKey, err := cipherSuite.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(" generate key pair failed : ", err)
	}
	secp256k1Handler := secp256k1.NewCipherSuite()
	privbytes, err := privKey.MarshalP()
	fmt.Printf("privKey : %x \n", privbytes)
	fmt.Println()
	pubKey := privKey.Public()
	pubbytes, err := secp256k1Handler.MarshalPublicKey(pubKey)
	fmt.Printf("pubKey : %x \n", pubbytes)
	fmt.Println()

	message := "test message"
	sign, err := privKey.Sign([]byte(message))
	if err != nil {
		fmt.Println(" sign message failed : ", err)
	}

	result := pubKey.Verify([]byte(message), sign)
	fmt.Println("verify : ", result)
}

func TestKeyStore_GenerateAddressKey(t *testing.T) {

	masterKey := newExtendedKey(SECP256K1)

	dbPath := "./~temp/TestGenerateKey/"
	os.RemoveAll(dbPath)
	//os.Mkdir(dbPath, 0777)
	db, err := createWalletDb(dbPath)
	if err != nil {
		log.Error(" can't create wallet database: ", err)
		return
	}

	err = walletdb.RecordUpdateTime(db)
	if err != nil {
		log.Warn("Failed to record update timestamp: ", err)
	}
	log.Debug(" wallet database create succeed !")

	// generate crypto key
	cryptoKey, err := GenerateCryptoKey()
	if err != nil {
		log.Error(" generate crypto key failed : ", err)
		return
	}
	log.Debugf(" your crypto key is : %x \n", cryptoKey)

	keyStore := NewKeyStore(db, cryptoKey)

	// case 1 : generate ecdsa address key
	accountKeyPriv, err := masterKey.DeriveAccountKey(DefaultAccountNum,
		SECP256K1)
	if err != nil {
		log.Error(" derive account key failed : ", err)
		return
	}
	defer accountKeyPriv.Zero()
	log.Debugf(" your  account private key is : %+v \n",
		accountKeyPriv)

	accountKeyPub, err := accountKeyPriv.PublicKey()
	if err != nil {
		log.Error(" derive account pulickey failed :", err)
		return
	}
	log.Debugf(" your  account public key is : %+v \n", accountKeyPub)

	// 加密default account key
	acctPrivKeyBytes, err := accountKeyPriv.Marshal()
	if err != nil {
		log.Error(" extended PrivateKey marshal failed : ", err)
		return
	}
	acctPrivKeyEnc, err := cryptoKey.Encrypt(acctPrivKeyBytes)
	if err != nil {
		log.Error(" extended Key crypto failed ")
		return
	}
	acctPubKeyBytes, err := accountKeyPub.Marshal()
	if err != nil {
		log.Error(" extended PublicKey marshal failed : ", err)
		return
	}
	acctPubKeyEnc, err := cryptoKey.Encrypt(acctPubKeyBytes)
	//生成default 账户的信息
	//组装accountInfo，并序列化
	assetList := make([]hash.HashType, 0)
	assetList = append(assetList, genesis.GenesisAsset)
	accountInfo := &AccountInfo{
		PrivKeyEnc: acctPrivKeyEnc,
		PubKeyEnc:  acctPubKeyEnc,

		ExternalIndex:         0,
		InternalIndex:         0,
		LastUsedExternalIndex: 0,
		LastUsedInternalIndex: 0,

		AccountName:  "default",
		AccountIndex: DefaultAccountNum,
		AccountType:  SECP256K1,
		AssetList:    assetList,
	}

	log.Debugf(" account info : %+v \n", accountInfo)

	_, addrKey, err := keyStore.GenerateAddressKey(accountInfo, true)
	if err != nil {
		t.Error(" generate addresskey failed.")
	}
	t.Logf("addrkey is : %+v \n", addrKey)

	// case 2 : generate bliss address key
	blissAccountKeyPriv, err := masterKey.DeriveAccountKey(DefaultAccountNum+1,
		BLISS)
	if err != nil {
		log.Error(" derive bliss account key failed : ", err)
		return
	}
	defer blissAccountKeyPriv.Zero()
	log.Debugf(" your bliss account private key is : %+v \n",
		blissAccountKeyPriv)

	blissAccountKeyPub, err := blissAccountKeyPriv.PublicKey()
	if err != nil {
		log.Error(" derive bliss account pulickey failed :", err)
		return
	}
	log.Debugf(" your bliss account public key is : %+v \n", blissAccountKeyPub)

	// 加密default account key
	blissAcctPrivKeyBytes, err := blissAccountKeyPriv.Marshal()
	if err != nil {
		log.Error("bliss account extended PrivateKey marshal failed : ", err)
		return
	}
	blissAcctPrivKeyEnc, err := cryptoKey.Encrypt(blissAcctPrivKeyBytes)
	if err != nil {
		log.Error(" bliss account extended Key crypto failed ")
		return
	}
	blissAcctPubKeyBytes, err := blissAccountKeyPub.Marshal()
	if err != nil {
		log.Error(" bliss account extended PublicKey marshal failed : ", err)
		return
	}
	blissAcctPubKeyEnc, err := cryptoKey.Encrypt(blissAcctPubKeyBytes)
	//生成default 账户的信息
	blissAccountInfo := &AccountInfo{
		PrivKeyEnc: blissAcctPrivKeyEnc,
		PubKeyEnc:  blissAcctPubKeyEnc,

		ExternalIndex:         0,
		InternalIndex:         0,
		LastUsedExternalIndex: 0,
		LastUsedInternalIndex: 0,

		AccountName:  "bliss",
		AccountIndex: DefaultAccountNum+1,
		AccountType:  BLISS,
		AssetList:    assetList,
	}
	log.Debugf(" bliss account info : %+v \n", accountInfo)

	_, blissAddrKey, err := keyStore.GenerateAddressKey(blissAccountInfo, false)
	if err != nil {
		t.Error(" generate addresskey failed: . ", err)
	}
	t.Logf("addrkey is : %+v \n", blissAddrKey)

	_, _, err = keyStore.GenerateAddressKey(blissAccountInfo, false)
}

func TestExtendedKey_DeriveAccountKey(t *testing.T) {
	parentKey := newExtendedKey(SECP256K1)

	//------------------------------ derive a ecdsa child key ---------------------------------------------
	ecdsaAccount, err := parentKey.DeriveAccountKey(1, SECP256K1)
	if err != nil {
		t.Error(" test : derive ecdsa account private key failed .")
		return
	}
	t.Logf("ecdsa account is : %+v \n", ecdsaAccount)
	t.Log(" test : derive ecdsa account private key succeed .\n")

	//------------------------------ derive a bliss child key ---------------------------------------------
	blissAccount, err := parentKey.DeriveAccountKey(1, BLISS)
	if err != nil {
		t.Error(" test : derive bliss account private key failed .")
		return
	}
	t.Logf("bliss account is : %+v \n", blissAccount)
	t.Log(" test : derive bliss account private key succeed .")

	//------------------------------ derive a bliss child key ---------------------------------------------
	_, err = parentKey.DeriveAccountKey(MaxAccountNum+1, BLISS)
	if err != nil {
		t.Log(" test : derive bliss account private key succeed .")
		return
	}
}

func TestExtendedKey_DeriveChildKey(t *testing.T) {
	parentKey := newExtendedKey(SECP256K1)

	//------------------------------ derive a ecdsa child key ---------------------------------------------
	ecdsaChild, err := parentKey.DeriveChildKey(1, SECP256K1)
	if err != nil {
		t.Error(" test : derive ecdsa private child failed .")
		return
	}
	t.Logf("ecdsa child is : %+v \n", ecdsaChild)
	t.Log(" test : derive ecdsa private child succeed .\n")

	//------------------------------ derive a bliss child key ---------------------------------------------
	blissChild, err := parentKey.DeriveChildKey(1, BLISS)
	if err != nil {
		t.Error(" test : derive bliss private child failed .")
		return
	}
	t.Logf("bliss child is : %+v \n", blissChild)
	t.Log(" test : derive bliss private child succeed .")

	//------------------------------ derive a bliss child key ---------------------------------------------
	parentKey = nil
	_, err = parentKey.DeriveChildKey(1, BLISS)
	if err != nil {
		t.Log(" test : derive bliss private child succeed .")
		return
	}
}

func TestExtendedKey_Child(t *testing.T) {

	masterkey := newExtendedKey(SECP256K1)
	t.Logf("master key is : %+v \n\n", masterkey)
	masterkeyPub, err := masterkey.PublicKey()
	if err != nil {
		t.Error("derive public key from privatekey failed .")
		return
	}
	t.Logf(" public master key is : %+v \n\n", masterkeyPub)

	//----------------------------derive ecdsa private child ------------------------------------------------
	ecdsaChild, err := masterkey.Child(1, true, SECP256K1)
	if err != nil {
		t.Error(" test : derive ecdsa private child failed .")
		return
	}
	t.Logf("priv . ecdsa child is : %+v \n", ecdsaChild)
	t.Log(" test : derive ecdsa private child from privatekey succeed .\n")

	ecdsapub, err := masterkeyPub.Child(1, true, SECP256K1)
	if err != nil {
		t.Error(" test : derive ecdsa private child failed .")
		return
	}
	t.Logf("pub . ecdsa child is : %+v \n", ecdsapub)
	t.Log(" test : derive ecdsa private child from publickey succeed .\n")

	//----------------------------derive bliss private child ------------------------------------------------
	blissChild, err := masterkey.Child(1, true, BLISS)
	if err != nil {
		t.Error(" test : derive bliss private child failed .")
		return
	}
	t.Logf("bliss child is : %+v \n", blissChild)
	t.Log(" test : derive bliss private child succeed .")

	//----------------------------derive private child from nil------------------------------------------------
	var key *ExtendedKey
	_, err = key.Child(2, false, BLISS)
	if err != nil {
		t.Log(" derive private child from nil succeed. ")
	}
}

func TestExtendedKey_DerivPrivKeys(t *testing.T) {
	masterKey := newExtendedKey(SECP256K1)

	privKeys, err := masterKey.DerivPrivKeys(0, 0, 5, SECP256K1)
	if err != nil {
		t.Error(" test derive privatekeys failed.")
		return
	}
	for _, privKey := range privKeys {
		t.Logf(" private key is : %+v \n", privKey)
	}
	t.Log("test derive privatekeys succeed.")
}

func TestExtendedKey_PublicKey(t *testing.T) {

	//---------------------------case1 derive public extendedkey from private extendedkey------------------------------------------
	extendedKey := newExtendedKey(SECP256K1)
	t.Logf("original extendedKey is : %+v \n", extendedKey)
	extendedPubKey, err := extendedKey.PublicKey()
	if err != nil {
		t.Error(" derive public extendedkey from private extendedkey failed .")
		return
	}
	t.Logf(" public extendedkey is : %+v \n", extendedPubKey)
	t.Log(" derive public extendedkeyfrom private extendedkey  succeed .")

	//---------------------------case2 derive public extendedkey from public extendedkey------------------------------------------
	extendedPubKey2, err := extendedPubKey.PublicKey()
	if err != nil {
		t.Error(" derive public extendedkey from public extendedkey failed .")
		return
	}
	t.Logf(" public extendedkey is : %+v \n", extendedPubKey2)
	t.Log(" derive public extendedkey from public extendedkey succeed .")

	//---------------------------case3 derive public extendedkey from wrong private extendedkey------------------------------------------
	version := []byte{12, 34, 44, 123}
	extendedKey.Version = version
	_, err = extendedKey.PublicKey()
	if err != nil {
		t.Log(" derive public extendedkey from wrong private extendedkey succeed .")
		return
	}
	t.Log(" derive public extendedkey from wrong private extendedkey failed .")

	//---------------------------case4 derive public extendedkey from nil ------------------------------------------
	var key ExtendedKey
	_, err = key.PublicKey()
	if err != nil {
		t.Log("test derive public extendedkey from nil succeed .")
		return
	}
	t.Log("test derive public extendedkey from nil failed .")
}

func TestExtendedKey_PublicKeyBytes(t *testing.T) {

	masterKey := newExtendedKey(SECP256K1)
	t.Logf("ecdsa privateKey's pubkey : %+v \n\n", masterKey)
	ecdsaExtendedKey, err := masterKey.DeriveChildKey(0, SECP256K1)
	if err != nil {
		t.Error(" derive childkey failed.")
		return
	}

	ecdsaPubkey := ecdsaExtendedKey.PublicKeyBytes()
	t.Logf(" ecdsa Public key bytes : %x \n", ecdsaPubkey)

	blissExtendedkey, err := masterKey.DeriveChildKey(1, BLISS)
	if err != nil {
		t.Error(" derive childkey failed.")
		return
	}
	blissPubkey := blissExtendedkey.PublicKeyBytes()
	t.Logf(" bliss Public key bytes : %x \n", blissPubkey)
}

func TestExtendedKey_Marshal(t *testing.T) {

	extendedKey := newExtendedKey(SECP256K1)
	t.Logf(" original extendedKey is : %+v \n", extendedKey)

	extendedKeyBytes, err := extendedKey.Marshal()
	if err != nil {
		t.Error(" extendedkey marshal test failed .")
		return
	}
	t.Logf(" extendedKeyBytes is : %x \n", extendedKeyBytes)
	t.Log(" extendedKey marshal test succeed. ")

	newExtendedKey := new(ExtendedKey)
	err = newExtendedKey.UnMarshal(extendedKeyBytes)
	if err != nil {
		t.Error(" extendedkey unmarshal test failed .")
		return
	}
	t.Logf(" extendedKey is : %+v \n", newExtendedKey)
	t.Log(" extendedKey unmarshal test succeed. ")
}

func TestExtendedKey_Zero(t *testing.T) {

	ecdsaExtendedKey := newExtendedKey(SECP256K1)
	ecdsaExtendedKey.Zero()
	t.Log(" extendedkey zore() test succeed. ")

	blissExtendedKey := newExtendedKey(BLISS)
	blissExtendedKey.Zero()
	t.Log(" extendedkey zore() test succeed. ")
}

func TestHDPrivateKeyToPublicKeyID(t *testing.T) {
	privKeyID := config.Parameters.HDPrivateKeyID

	pubKeyID, err := HDPrivateKeyToPublicKeyID(privKeyID[:])
	if err != nil {
		t.Error(" HDPrivateKeyToPublicKeyID test failed. ")
		return
	}
	t.Logf(" public key ID is :%v \n", pubKeyID)
	t.Log(" HDPrivateKeyToPublicKeyID test succeed.")
}

func TestNewAccountInfo(t *testing.T) {
	acctPrivKeyEncStr := "f58b3a06f78d0e7c7da0ba4133dc54f41c641728654f852600d1f64a314395430c6f803f7adabbd5193138544347c8445e057ad5f8ecc4e84c709687153fd2e9b9a591bc86b63e0a8ce14e088aacf4988dee399a8e91b7943da7e5a8718f8f1954a7f07aa13f695a776041b4809a0dbe0b320666c7834ed6bdf1c52e0d1bb92b14d33e3a38fdf2e129983c6763df825796d40318496b522b162e9521a2330c99785e211649e7959c65e0747187cddb618378382961b3cf227df52ce2d1c62f7bd15a226a7e8fc13c14c3de77a57b94bde98f059b31fd6828fc228bd4387f3cd2a89972fbddaf5bdb56a58ca968d0837b906ef6bf164cb0f3fd7eef4e71d7f9a79b85eb"
	acctPubKeyEncStr := "05a236b25d0b5bd68f1291528c9833796617e9cad1a21f5b1b96902357e58b6a4b337a514327240c12da757c40ce79a69beecd0493ecebf86fe09e8aa94e56bae1e1808ba1d8593accfebe1d0e0ccec75ececb14ea319d6c60cf3d5f0871af833ab357268d15f06d87f8511f9c3a931d2dc552d5beb99b59cbba6029f68b7861d2b1de004f8d411159fa862074b061f7e0ce73d8ce235ed5d53925d995034d0da5fcb0a4bf65c736eb047f4de1888c0f31678b77386a4ef2dfc760206aeec33ee6585db58d4ca5815fd8701ead6b9dc899ca62d57221973215ffe387043df5f0daa9f08d22acba1938028652c3fff67d5948bfa970240729fad445360f45c4180911"

	acctPrivKeyEnc, err := hex.DecodeString(acctPrivKeyEncStr)
	if err != nil {
		t.Error(" hex string decode failed ")
		return
	}

	acctPubKeyEnc, err := hex.DecodeString(acctPubKeyEncStr)
	if err != nil {
		t.Error(" hex string decode failed ")
		return
	}
	acctName := "testacct"
	assetList := make([]hash.HashType, 0)
	assetList = append(assetList, genesis.GenesisAsset)
	acctInfo := &AccountInfo{
		PrivKeyEnc: acctPrivKeyEnc,
		PubKeyEnc:  acctPubKeyEnc,

		ExternalIndex:         0,
		InternalIndex:         0,
		LastUsedExternalIndex: 0,
		LastUsedInternalIndex: 0,

		AccountName:  acctName,
		AccountIndex: 1,
		AccountType:  SECP256K1,
		AssetList:    assetList,
	}
	t.Logf("new accountinfo is : %+v\n", acctInfo)
	t.Log(" new accountInfo test succeed. ")
}

func TestAccountInfo_Marshal(t *testing.T) {

	acctPrivKeyEncStr := "f58b3a06f78d0e7c7da0ba4133dc54f41c641728654f852600d1f64a314395430c6f803f7adabbd5193138544347c8445e057ad5f8ecc4e84c709687153fd2e9b9a591bc86b63e0a8ce14e088aacf4988dee399a8e91b7943da7e5a8718f8f1954a7f07aa13f695a776041b4809a0dbe0b320666c7834ed6bdf1c52e0d1bb92b14d33e3a38fdf2e129983c6763df825796d40318496b522b162e9521a2330c99785e211649e7959c65e0747187cddb618378382961b3cf227df52ce2d1c62f7bd15a226a7e8fc13c14c3de77a57b94bde98f059b31fd6828fc228bd4387f3cd2a89972fbddaf5bdb56a58ca968d0837b906ef6bf164cb0f3fd7eef4e71d7f9a79b85eb"
	acctPubKeyEncStr := "05a236b25d0b5bd68f1291528c9833796617e9cad1a21f5b1b96902357e58b6a4b337a514327240c12da757c40ce79a69beecd0493ecebf86fe09e8aa94e56bae1e1808ba1d8593accfebe1d0e0ccec75ececb14ea319d6c60cf3d5f0871af833ab357268d15f06d87f8511f9c3a931d2dc552d5beb99b59cbba6029f68b7861d2b1de004f8d411159fa862074b061f7e0ce73d8ce235ed5d53925d995034d0da5fcb0a4bf65c736eb047f4de1888c0f31678b77386a4ef2dfc760206aeec33ee6585db58d4ca5815fd8701ead6b9dc899ca62d57221973215ffe387043df5f0daa9f08d22acba1938028652c3fff67d5948bfa970240729fad445360f45c4180911"

	acctPrivKeyEnc, err := hex.DecodeString(acctPrivKeyEncStr)
	if err != nil {
		t.Error(" hex string decode failed ")
		return
	}

	acctPubKeyEnc, err := hex.DecodeString(acctPubKeyEncStr)
	if err != nil {
		t.Error(" hex string decode failed ")
		return
	}
	acctName := "testacct"
	accountInfo := &AccountInfo{
		PrivKeyEnc:            acctPrivKeyEnc,
		PubKeyEnc:             acctPubKeyEnc,
		ExternalIndex:         0,
		InternalIndex:         0,
		LastUsedExternalIndex: 0,
		LastUsedInternalIndex: 0,
		AccountName:           acctName,
		AccountType:           SECP256K1,
	}

	accountInfoBytes, err := accountInfo.EncodeAccountInfo()
	if err != nil {
		t.Error(" accountinfo masrshal failed.")
		return
	}
	t.Logf("accountinfo bytes is : %x \n", accountInfoBytes)

	assertBytes, _ := hex.DecodeString("ffaeff810301010b4163636f756e74496e666f01ff82000108010a507269764b6579456e63010a0001095075624b6579456e63010a00010d45787465726e616c496e646578010600010d496e7465726e616c496e64657801060001154c6173745573656445787465726e616c496e64657801060001154c61737455736564496e7465726e616c496e646578010600010b4163636f756e744e616d65010c00010b4163636f756e74547970650104000000fe021aff8201fe0103f58b3a06f78d0e7c7da0ba4133dc54f41c641728654f852600d1f64a314395430c6f803f7adabbd5193138544347c8445e057ad5f8ecc4e84c709687153fd2e9b9a591bc86b63e0a8ce14e088aacf4988dee399a8e91b7943da7e5a8718f8f1954a7f07aa13f695a776041b4809a0dbe0b320666c7834ed6bdf1c52e0d1bb92b14d33e3a38fdf2e129983c6763df825796d40318496b522b162e9521a2330c99785e211649e7959c65e0747187cddb618378382961b3cf227df52ce2d1c62f7bd15a226a7e8fc13c14c3de77a57b94bde98f059b31fd6828fc228bd4387f3cd2a89972fbddaf5bdb56a58ca968d0837b906ef6bf164cb0f3fd7eef4e71d7f9a79b85eb01fe010205a236b25d0b5bd68f1291528c9833796617e9cad1a21f5b1b96902357e58b6a4b337a514327240c12da757c40ce79a69beecd0493ecebf86fe09e8aa94e56bae1e1808ba1d8593accfebe1d0e0ccec75ececb14ea319d6c60cf3d5f0871af833ab357268d15f06d87f8511f9c3a931d2dc552d5beb99b59cbba6029f68b7861d2b1de004f8d411159fa862074b061f7e0ce73d8ce235ed5d53925d995034d0da5fcb0a4bf65c736eb047f4de1888c0f31678b77386a4ef2dfc760206aeec33ee6585db58d4ca5815fd8701ead6b9dc899ca62d57221973215ffe387043df5f0daa9f08d22acba1938028652c3fff67d5948bfa970240729fad445360f45c41809110508746573746163637400")

	if bytes.Equal(accountInfoBytes, assertBytes) {
		t.Log("accountinfo marshal test succeed.")
	}

	acctInfo := new(AccountInfo)
	err = acctInfo.DecodeAccountInfo(accountInfoBytes)
	if err != nil {
		t.Error(" accountinfo unmarshal test failed. ")
		return
	}
	t.Logf("unmarshaled accouninfo is : %+v \n", acctInfo)
	t.Log("accountinfo unmarshal test succeed.")
}

//private key encode err
func TestDbPutKeyPair1(t *testing.T) {
	log.Init(config.Parameters.MaxLogSize, config.Parameters.LogLevel, config.DefaultLogDir+"/", log.Stdout)
	dbPath := "./~temp/TestPutKeyPair/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	DeCompress(testdata, dbPath)
	db, err := openDb(dbPath)
	if err != nil {
		fmt.Println("can't open db : ", err)
	}
	defer func() {
		db.Close()
		os.RemoveAll(config.Parameters.DataDir)
	}()

	key := &ExtendedKey{
		Version:   []byte("123"),
		Depth:     1,
		IsPrivate: true,
		AlgType:   1,
	}
	pubkey := &ExtendedKey{
		Version:   []byte("123"),
		Depth:     1,
		IsPrivate: true,
		AlgType:   1,
	}
	err = dbPutKeyPair(db, key, pubkey)
	if err == nil {
		t.Error(" 测试出错")
	} else {
		t.Log("测试通过")
	}

}

//public key encode err
func TestDbPutKeyPair2(t *testing.T) {
	log.Init(config.Parameters.MaxLogSize, config.Parameters.LogLevel, config.DefaultLogDir+"/", log.Stdout)
	dbPath := "./~temp/TestPutKeyPair2/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	DeCompress(testdata, dbPath)
	db, err := openDb(dbPath)
	if err != nil {
		fmt.Println("can't open db : ", err)
	}
	defer func() {
		db.Close()
		os.RemoveAll(config.Parameters.DataDir)
	}()

	privkeyStr := "63fa343aa09fa0a8a92321badb5d07e29b64a9902b85f2b8a6f9f718346aa366"
	privBytes, err := hex.DecodeString(privkeyStr)
	if err != nil {
		t.Error(" decoding privateKey string failed : ", err)
		return
	}
	secp256k1Handler := secp256k1.NewCipherSuite()
	privkey, err := secp256k1Handler.UnmarshalPrivateKey(privBytes)
	if err != nil {
		t.Error(" decodeing privateKey bytes failed : ", err)
	}
	t.Log("privkey : ", privkey)
}

func newExtendedKey(altType int) *ExtendedKey {
	var privKey *big.Int
	var privBytes []byte
	var chainCode []byte

	for {
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			continue
		}
		hmac512 := hmac.New(sha512.New, []byte("test"))
		hmac512.Write(seed)
		l := hmac512.Sum(nil)
		privBytes = l[:32]
		chainCode = l[32:]
		privKey = new(big.Int).SetBytes(privBytes)
		if privKey.Cmp(btcec.S256().N) >= 0 || privKey.Sign() == 0 {
			continue
		}
		break
	}
	parentFP := []byte{12, 34, 24, 67}

	extendedKey := &ExtendedKey{
		Version:     config.Parameters.HDPrivateKeyID[:],
		Depth:       1,
		ParentFP:    parentFP,
		ChainCode:   chainCode,
		ChildNumber: 0,
		Key:         privBytes,
		IsPrivate:   true,
		AlgType:     altType,
	}

	return extendedKey
}

func createWalletDb(dbfile string) (database.DB, error) {

	// 判断钱包是否存在
	log.Debug(" data dir : ", dbfile)
	exist, err := utils.FileExists(dbfile)
	if err != nil {
		log.Error(" check wallet exist failed : ", err)
		return nil, err
	}
	if exist {
		return nil, errors.New(" the wallet already exist. ")
	}

	// 创建钱包
	db, err := database.Create("badgerDB", dbfile, dbfile)
	if err != nil {
		return nil, err
	}

	log.Debug("create database bucket ")
	err = walletdb.CreateWalletBucket(db)
	if err != nil {
		fmt.Println(" create bucket failed : ", err)
		return nil, err
	}

	return db, nil
}
