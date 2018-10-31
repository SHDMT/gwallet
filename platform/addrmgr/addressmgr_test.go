package addrmgr

import (
	"archive/zip"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/SHDMT/gravity/infrastructure/crypto/hash"
	"github.com/SHDMT/gwallet/infrastructure/config"
	"github.com/SHDMT/gwallet/infrastructure/database"
	_ "github.com/SHDMT/gwallet/infrastructure/database/badgerdb"
	"github.com/SHDMT/gwallet/infrastructure/log"
	"github.com/SHDMT/gwallet/platform/walletdb"
	"io"
	"os"
	"strings"
	"testing"
)

const (
	dbName = "badgerDB"
	testdata = "../testdata/wallet_test_data5.zip"
)
const (
	checkMark = "\u2713"
	ballotX   = "\u2717"
)

func TestNewAddressManager(t *testing.T) {
	log.Init(config.Parameters.MaxLogSize, config.Parameters.LogLevel, config.DefaultLogDir+"/", log.Stdout)
	dbPath := "./~temp/TestNewAddressMgr/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	DeCompress(testdata, dbPath)
	db, err := openDb(dbPath)
	if err != nil {
		t.Errorf("can't open db : %v", err)
	}

	defer func() {
		db.Close()
		os.RemoveAll(config.Parameters.DataDir)
	}()

	keystore := NewKeyStore(db, nil)
	fmt.Println("1", keystore)
	addrmgr := NewAddressManager(keystore, db)
	fmt.Println("2", addrmgr)

	t.Logf(" address manager create sucessed : %+v \n", addrmgr)
	addrmgr2 := NewAddressManager(nil, db)
	t.Logf(" address manager 2 create sucessed : %+v \n", addrmgr2)

}

func TestNewAddress(t *testing.T) {
	log.Init(config.Parameters.MaxLogSize, config.Parameters.LogLevel, config.DefaultLogDir+"/", log.Stdout)

	dbPath := "./~temp/TestNewAddress/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	DeCompress(testdata, dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}
	defer func() {
		if db != nil {
			db.Close()
		}
	}()

	password := []byte("flq")
	var cryptoKey = new(CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		t.Error(" -- ")
	}
	log.Debugf("cryptokeyEnc is >>: %x \n", cryptoKeyEnc)

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		log.Error(" can't load secretKey from database, please retry again")
		return
	}

	var secretkey SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		log.Error(" test : create new secret key failed . ")
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		log.Error(" can't derive secret key : ", err)
	}
	log.Debugf("secretkey is >>: %x \n", secretkey.Marshal())

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		log.Error(" decrypt Cryptokey failed : ", err)
	}
	log.Debugf("cryptoKeyDec >>: %x \n", cryptoKeyDec)
	copy(cryptoKey[:], cryptoKeyDec)

	keystore := NewKeyStore(db, cryptoKey)
	addrmgr := NewAddressManager(keystore, db)

	// ----------------------------------- case 1 create new external address with account name
	addr, err := addrmgr.NewAddress("default", false)
	if err != nil {
		fmt.Println(" generate address failed ")
	}
	fmt.Printf("address : %+v \n", addr)
	walletdb.PrintDBWithBase64(db, []byte("address"))
	walletdb.PrintDBWithBase64(db, []byte("publicKey-privateKey"))

	// ------------------------------------ case 2 create new external address
	addr2, err := addrmgr.NewAddress("default", false)
	if err != nil {
		fmt.Println(" generate address failed ")
	}
	fmt.Printf("address : %+v \n", addr2)
	walletdb.PrintDBWithBase64(db, []byte("address"))
	walletdb.PrintDBWithBase64(db, []byte("publicKey-privateKey"))

	// ------------------------------------ case 3 create new internal address
	addr3, err := addrmgr.NewAddress("", true)
	if err != nil {
		fmt.Println(" generate address failed ")
	}
	fmt.Printf("address : %+v \n", addr3)
	walletdb.PrintDBWithBase64(db, []byte("address"))
	walletdb.PrintDBWithBase64(db, []byte("publicKey-privateKey"))

	// ------------------------------------ case 4 create new internal address with wrong account name
	_, err = addrmgr.NewAddress("1234", true)
	if err != nil {
		t.Log(" test:  create new internal address with wrong account name succeed")
	}
}

func TestAddressManager_CreateNewAddress(t *testing.T) {
	dbPath := "./~temp/TestCreateNewAddress/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	DeCompress(testdata, dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}
	defer func() {
		if db != nil {
			db.Close()
		}
	}()

	password := []byte("flq")
	var cryptoKey = new(CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		t.Error(" -- ")
	}
	log.Debugf("cryptokeyEnc is >>: %x \n", cryptoKeyEnc)

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		log.Error(" can't load secretKey from database, please retry again")
		return
	}

	var secretkey SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		log.Error(" test : create new secret key failed . ")
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		log.Error(" can't derive secret key : ", err)
	}
	log.Debugf("secretkey is >>: %x \n", secretkey.Marshal())

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		log.Error(" decrypt Cryptokey failed : ", err)
	}
	log.Debugf("cryptoKeyDec >>: %x \n", cryptoKeyDec)
	copy(cryptoKey[:], cryptoKeyDec)

	keystore := NewKeyStore(db, cryptoKey)
	addrmgr := NewAddressManager(keystore, db)

	_, err = addrmgr.CreateNewAddress(5, false)
	if err != nil {
		t.Log("test : create new address succeed.")
	}
}

func TestGetAddressByPubKey(t *testing.T) {

	dbPath := "./~temp/TestGetAddressByPubKey/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	DeCompress(testdata, dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}
	defer func() {
		if db != nil {
			db.Close()
		}
	}()

	pubKeyStr := ""
	pubKey, err := hex.DecodeString(pubKeyStr)
	if err != nil {
		t.Error("can't parse pubkey string.")
		return
	}
	addr, err := GetAddressByPubBytes(db, ImportedAccountNum, false, true, 0, pubKey)
	t.Logf("new address is : %+v \n", addr)
	t.Log(" test : get new address by pubkey succeed.")
}

func TestAddressManager_ValidateAddress(t *testing.T) {

	dbPath := "./~temp/TestValidateAddress/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	DeCompress(testdata, dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}
	defer func() {
		if db != nil {
			db.Close()
		}
	}()

	password := []byte("flq")
	// 从数据库中取出cryptoKkey
	var cryptoKey = new(CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		return
	}

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		log.Error(" can't load secretKey from database, please retry again")
		return
	}
	var secretkey SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		log.Error(" test : create new secret key failed . ")
		return
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		log.Error(" can't derive secret key : ", err)
		return
	}

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		log.Error(" decrypt Cryptokey failed : ", err)
		return
	}
	copy(cryptoKey[:], cryptoKeyDec)

	keystrore := NewKeyStore(db, cryptoKey)

	// ----------------------- case 1 validate address
	// 创建 addressManager 对象
	addrMgr := NewAddressManager(keystrore, db)
	address, err := addrMgr.CreateNewAddress(1, false)
	if err != nil {
		t.Error("can't get new address.")
		return
	}
	addrStr := base64.StdEncoding.EncodeToString(address.Address)

	response := addrMgr.ValidateAddress(addrStr)
	t.Logf(" validateaddress :  %+v \n", response)
	if response.IsValid {
		t.Log("test : validate address succeed . ")
	} else {
		t.Log("test : validate address failed . ")
	}
	// ----------------------- case 2 validate wrong base64 address
	addrStr = "sadjgjfksdadgggggjdghjsadg"
	response = addrMgr.ValidateAddress(addrStr)
	if !response.IsValid {
		t.Log("test : validate address succeed . ")
	} else {
		t.Log("test : validate address failed . ")
	}
	// ----------------------- case 3 validate not exist address
	addrStr = "DQgVkerobo00hhrb6vTnGDOKxnYoX+FdZzhEZAZ+uTA="
	response = addrMgr.ValidateAddress(addrStr)
	if !response.IsValid {
		t.Log("test : validate address succeed . ")
	} else {
		t.Log("test : validate address failed . ")
	}
}

func TestAddressManager_GetImportedAddress(t *testing.T) {
	dbPath := "./~temp/TestValidateAddress/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	DeCompress(testdata, dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}
	defer func() {
		if db != nil {
			db.Close()
		}
	}()

	password := []byte("flq")
	// 从数据库中取出cryptoKkey
	var cryptoKey = new(CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		return
	}

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		log.Error(" can't load secretKey from database, please retry again")
		return
	}
	var secretkey SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		log.Error(" test : create new secret key failed . ")
		return
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		log.Error(" can't derive secret key : ", err)
		return
	}

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		log.Error(" decrypt Cryptokey failed : ", err)
		return
	}
	copy(cryptoKey[:], cryptoKeyDec)

	keystrore := NewKeyStore(db, cryptoKey)

	// 创建 addressManager 对象
	addrMgr := NewAddressManager(keystrore, db)

	addrStr := "s9kyQVdVBQ32xyiivZiblo2BHvSFZ0ijYTWtaCYtjd4="
	addr, err := addrMgr.GetImportedAddress("11111112SEe6qhJ11bboJPH8HNUxaDY4j2vF3LDGDriyn2HXJ1WevEBRFN82khKEvGDk")
	if err != nil {
		t.Error("can't get imported address by wif string.")
		return
	}
	getaddr := base64.StdEncoding.EncodeToString(addr.Address)
	if getaddr == addrStr {
		t.Log(" test : get imported address by wif string succeed")
	}

	_, err = addrMgr.GetImportedAddress("1111111F3LDGDriyn2HXJ1WevEBRFN82khKEvGDk")
	if err != nil {
		t.Log("test : get imported address by wif string succeed.")
	}

	_, err = addrMgr.GetImportedAddress("11111112SEe6qhJ11bdk3ZWaKDudoMMeRwVs3HXrzmqbVfzNAo9j2UL79Mn39C2khJQg")
	if err != nil {
		t.Log("test : get imported address by wif string succeed.")
		return
	}
	t.Error(" test : get imported address by wif string failed. ")
}

func TestAddressManager_RecoverAllUsedAddress(t *testing.T) {

	dbPath := "./~temp/TestValidateAddress/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	DeCompress(testdata, dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}
	defer func() {
		if db != nil {
			db.Close()
		}
	}()

	password := []byte("flq")
	// 从数据库中取出cryptoKkey
	var cryptoKey = new(CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		return
	}

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		log.Error(" can't load secretKey from database, please retry again")
		return
	}
	var secretkey SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		log.Error(" test : create new secret key failed . ")
		return
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		log.Error(" can't derive secret key : ", err)
		return
	}

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		log.Error(" decrypt Cryptokey failed : ", err)
		return
	}
	copy(cryptoKey[:], cryptoKeyDec)

	keystrore := NewKeyStore(db, cryptoKey)

	// 创建 addressManager 对象
	addrMgr := NewAddressManager(keystrore, db)

	accountInfo, err := dbFetchAccountInfo(db, 1)
	if err != nil {
		t.Error("can't fetch account info from database.")
		return
	}
	acctPrivKeyBytes, err := cryptoKey.Decrypt(accountInfo.PrivKeyEnc)
	if err != nil {
		t.Error(" can't decrypto private key")
		return
	}
	acctPrivKey := new(ExtendedKey)
	err = acctPrivKey.UnMarshal(acctPrivKeyBytes)
	if err != nil {
		t.Error("can't unmarshal account private key")
		return
	}
	err = addrMgr.RecoverAllUsedAddress(acctPrivKey, 3, 0, 0, 5)
	if err != nil {
		t.Error(" can't recover used address . ")
		return
	}
	t.Log(" test : recover all used address succeed.")

	err = addrMgr.RecoverAllUsedAddress(acctPrivKey, 3, 1, 0, 5)
	if err != nil {
		t.Error(" can't recover used address . ")
		return
	}
	t.Log(" test : recover all used address succeed.")

	err = addrMgr.RecoverAllUsedAddress(acctPrivKey, 3, 1, 5, 5)
	if err != nil {
		t.Error(" can't recover used address . ")
		return
	}
	t.Log(" test : recover all used address succeed.")
}

func TestAddressManager_CreateNewAccount(t *testing.T) {
	dbPath := "./~temp/TestValidateAddress/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	DeCompress(testdata, dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}
	defer func() {
		if db != nil {
			db.Close()
		}
	}()

	password := []byte("flq")
	// 从数据库中取出cryptoKkey
	var cryptoKey = new(CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		return
	}

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		log.Error(" can't load secretKey from database, please retry again")
		return
	}
	var secretkey SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		log.Error(" test : create new secret key failed . ")
		return
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		log.Error(" can't derive secret key : ", err)
		return
	}

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		log.Error(" decrypt Cryptokey failed : ", err)
		return
	}
	copy(cryptoKey[:], cryptoKeyDec)

	keystrore := NewKeyStore(db, cryptoKey)

	// 创建 addressManager 对象
	addrMgr := NewAddressManager(keystrore, db)

	_, addr, err := addrMgr.CreateNewAccount(cryptoKey, "testAcct", SECP256K1)
	if err != nil {
		t.Error(" can't create new account.")
	}
	t.Logf("new account first address is : %+v \n", addr)
	t.Log("test : create new acount succeed. ")

	// ------------------------- case 2 : create new account with wrong crypto
	_, _, err = addrMgr.CreateNewAccount(cryptoKey, "testAcct", SECP256K1)
	if err != nil {
		t.Log(" test : create new acount succeed.")
	}
	// ------------------------- case 3 : create new account with wrong algType
	_, _, err = addrMgr.CreateNewAccount(cryptoKey, "testAcct", 3)
	if err != nil {
		t.Log(" test : create new acount succeed.")
	}
}

func TestValidateAccountName(t *testing.T) {

	acctName := ""
	// ----------------------case 1 validate account name with ""
	err := ValidateAccountName(acctName)
	if err != nil {
		t.Log(" validate account name with null string succeed. ")
	} else {
		t.Error("validate account name with null string failed.")
	}

	// ---------------------case 2 validate account Name with "*"
	acctName = "*"
	err = ValidateAccountName(acctName)
	if err != nil {
		t.Log(" validate account name with * succeed.")
	} else {
		t.Error("validate account name with * failed.")
	}

	// ---------------------case 3 validate account Name with "default"
	acctName = "default"
	err = ValidateAccountName(acctName)
	if err != nil {
		t.Log("validate account name with default succeed. ")
	} else {
		t.Error("validate account name with default failed.")
	}

	// ---------------------case 4 validate account Name with "1234"
	acctName = "1234"
	err = ValidateAccountName(acctName)
	if err != nil {
		t.Error("validate account name with 1234 failed. ")
		return
	}
	t.Log(" validate account name with 1234 succeed.")
}

func TestAddress_Hash160(t *testing.T) {

	pubkey := "047ec60fb584942a99c3b690899b306b38d32ab8cc8811b713461e89985fb97f603d59bb0cef74c842c94b7cae0710461df644abb09236c7e371564dc40263905c"
	pubkeyBytes, err := hex.DecodeString(pubkey)
	if err != nil {
		t.Error(" decode pubkey bytes failed : ", err)
		return
	}
	pubkeyHash := hash.Sum256(pubkeyBytes)
	address := NewAddress(0, pubkeyHash, false, false, 0, pubkeyBytes)

	addrHash, err := address.Hash160()
	if err != nil {
		t.Error(" can't degiest address : ", err)
		return
	}
	t.Logf(" Hash160 Address : %x ", addrHash)
}

func TestEncodeAddress(t *testing.T) {
	pubkey := "047ec60fb584942a99c3b690899b306b38d32ab8cc8811b713461e89985fb97f603d59bb0cef74c842c94b7cae0710461df644abb09236c7e371564dc40263905c"
	pubkeyBytes, err := hex.DecodeString(pubkey)
	if err != nil {
		t.Error(" decoding pubkey bytes failed : ", err)
		return
	}
	pubkeyHash := hash.Sum256(pubkeyBytes)
	address := NewAddress(0, pubkeyHash, false, false, 0, pubkeyBytes)

	addrBytes, err := EncodeAddress(address)
	if err != nil {
		t.Error(" Encoded address failes : ", err)
		return
	}
	t.Logf(" Encoded address :  %x \n", addrBytes)
}

func TestDecodeAddress(t *testing.T) {

	addrStr := "52ff81030101074164647265737301ff8200010501074163636f756e74010600010741646472657373010a000108496e7465726e616c0102000108496d706f7274656401020001065075624b6579010a00000068ff820220c9a255c1a1e2377b388e19c83f31a853335f739db2941e371704096f4f141a480341047ec60fb584942a99c3b690899b306b38d32ab8cc8811b713461e89985fb97f603d59bb0cef74c842c94b7cae0710461df644abb09236c7e371564dc40263905c00"
	addrBytes, err := hex.DecodeString(addrStr)
	if err != nil {
		t.Error(" decoding address string failed : ", err)
		return
	}
	address, err := DecodeAddress(addrBytes)
	if err != nil {
		t.Error(" decoding address bytes failed : ", err)
		return
	}
	t.Logf("address pubkey : %x \n", address.PubKey)
}

func TestAddressManager_SetDb(t *testing.T) {
	dbPath := "./~temp/TestSetDB/"
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

	addrmgr := NewAddressManager(nil, nil)
	addrmgr.SetDb(db)
	if addrmgr.db == nil {
		t.Error(" address manager set database failed . ")
	}
	t.Logf(" address manager set database succeed . ")
}

func TestAddressManager_SetKeyStore(t *testing.T) {

	keystore := NewKeyStore(nil, nil)

	addrmgr := NewAddressManager(nil, nil)
	addrmgr.SetKeyStore(keystore)
	if addrmgr.keyStore == nil {
		t.Error(" address manager set keystore failed . ")
	}
	t.Logf(" address manager set keystore succeed . ")
}

func openDb(dbPath string) (database.DB, error) {
	var db database.DB
	db, err := database.Open("badgerDB", dbPath, dbPath)
	if err != nil {
		return nil, err
	}
	err = walletdb.RecordUpdateTime(db)
	if err != nil {
		log.Warn("Failed to update record timestamp\n")
	}

	return db, nil
}

func DeCompress(zipFile, dest string) error {
	reader, err := zip.OpenReader(zipFile)
	if err != nil {
		return err
	}
	defer reader.Close()
	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		filename := dest + file.Name
		err = os.MkdirAll(getDir(filename), 0755)
		if err != nil {
			return err
		}
		w, err := os.Create(filename)
		if err != nil {
			return err
		}
		defer w.Close()
		_, err = io.Copy(w, rc)
		if err != nil {
			return err
		}
		w.Close()
		rc.Close()
	}
	return nil
}
func getDir(path string) string {
	return subString(path, 0, strings.LastIndex(path, "/"))
}

func subString(str string, start, end int) string {
	rs := []rune(str)
	length := len(rs)

	if start < 0 || start > length {
		panic("start is wrong")
	}

	if end < start || end > length {
		panic("end is wrong")
	}

	return string(rs[start:end])
}
func dbFetchSecretKey(db database.DB) ([]byte, error) {
	var secretKey []byte
	err := db.View(func(tx database.Tx) error {
		var err error
		secretKey, err = walletdb.DbFetchSecretKey(tx)
		return err
	})

	if err != nil {
		return nil, err
	}
	return secretKey, nil
}
func dbFetchCryptoKey(db database.DB) ([]byte, error) {

	var cryptokey []byte
	err := db.View(func(tx database.Tx) error {
		var err error
		cryptokey, err = walletdb.DbFetchCryptoKey(tx)

		return err
	})
	if err != nil {
		return nil, err
	}
	return cryptokey, nil
}
