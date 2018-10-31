package message

import (
	"archive/zip"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/SHDMT/gravity/infrastructure/crypto/hash"
	"github.com/SHDMT/gwallet/infrastructure/database"
	"github.com/SHDMT/gwallet/platform/addrmgr"
	"github.com/SHDMT/gwallet/platform/proto"
	"github.com/SHDMT/gwallet/platform/utxo"
	"github.com/SHDMT/gwallet/platform/walletdb"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/SHDMT/gravity/platform/consensus/structure"
	_ "github.com/SHDMT/gwallet/infrastructure/database/badgerdb"
)

const (
	dbName = "badgerDB"
	testdata1 = "../testdata/wallet_test_data1.zip"
	testdata2 = "../testdata/wallet_test_data2.zip"
)
const (
	checkMark = "\u2713"
	ballotX   = "\u2717"
)

func TestMessageKeySerializeAndDeserialize(t *testing.T) {
	mk := &MsgKey{
		unitHash: new(structure.Unit).Hash(),
		id:       2,
	}

	mkBytes := mk.Serialize()

	messageKey := new(MsgKey)
	messageKey.Deserialize(mkBytes)

	fmt.Println(&mk == &messageKey)
	if reflect.DeepEqual(mk, messageKey) {
		t.Logf("测试通过%v", checkMark)
	} else {
		t.Fatalf("测试出错%v", ballotX)
	}
}

func TestNewMessageManager(t *testing.T) {

	dbPath := "./~temp/TestNewMessageManager/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testdata1, dbPath)
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
	var cryptoKey = new(addrmgr.CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		t.Error(" fetch crypto key failed .")
		return
	}

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		t.Error(" can't load secretKey from database, please retry again")
		return
	}
	var secretkey addrmgr.SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		t.Error(" test : create new secret key failed . ")
		return
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		t.Error(" can't derive secret key : ", err)
		return
	}

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		t.Error(" decrypt Cryptokey failed : ", err)
		return
	}
	copy(cryptoKey[:], cryptoKeyDec)

	keystrore := addrmgr.NewKeyStore(db, cryptoKey)

	// 创建 addressManager 对象
	addrMgr := addrmgr.NewAddressManager(keystrore, db)

	// 创建 UnspentManager 对象
	utxoMgr := utxo.NewUTXOManager(db)

	// 创建 messageManager 对象
	messageMgr, err := NewTXManager(db, utxoMgr, addrMgr)
	if err != nil {
		t.Error("can't create messageManager : ", err)
		return
	}
	t.Logf(" messageMgr : %+v \n ", messageMgr)
	t.Log(" test case : create messageManager succeed .")
}

func TestMessageManager_LoadAccounts(t *testing.T) {
	dbPath := "./~temp/TestLoadAccounts/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testdata1, dbPath)
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
	var cryptoKey = new(addrmgr.CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		t.Error(" fetch crypto key failed .")
		return
	}

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		t.Error(" can't load secretKey from database, please retry again")
		return
	}
	var secretkey addrmgr.SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		t.Error(" test : create new secret key failed . ")
		return
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		t.Error(" can't derive secret key : ", err)
		return
	}

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		t.Error(" decrypt Cryptokey failed : ", err)
		return
	}
	copy(cryptoKey[:], cryptoKeyDec)

	keystrore := addrmgr.NewKeyStore(db, cryptoKey)

	// 创建 addressManager 对象
	addrMgr := addrmgr.NewAddressManager(keystrore, db)

	// 创建 UnspentManager 对象
	utxoMgr := utxo.NewUTXOManager(db)

	// 创建 messageManager 对象
	messageMgr, err := NewTXManager(db, utxoMgr, addrMgr)
	if err != nil {
		t.Error("can't create messageManager : ", err)
		return
	}
	amount, wallets, err := messageMgr.LoadAccounts()
	if err != nil {
		t.Error(" can't load accounts .")
		return
	}
	t.Log("wallet amount : ", amount)
	t.Logf("wallet account : %+v \n", wallets)
}

func TestMessageManager_CreatePaymentMessage(t *testing.T) {
	dbPath := "./~temp/TestCreatePayments/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testdata1, dbPath)
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
	var cryptoKey = new(addrmgr.CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		t.Error(" fetch crypto key failed .")
		return
	}

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		t.Error(" can't load secretKey from database, please retry again")
		return
	}
	var secretkey addrmgr.SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		t.Error(" test : create new secret key failed . ")
		return
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		t.Error(" can't derive secret key : ", err)
		return
	}

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		t.Error(" decrypt Cryptokey failed : ", err)
		return
	}
	copy(cryptoKey[:], cryptoKeyDec)

	keystrore := addrmgr.NewKeyStore(db, cryptoKey)

	// 创建 addressManager 对象
	addrMgr := addrmgr.NewAddressManager(keystrore, db)

	// 创建 UnspentManager 对象
	utxoMgr := utxo.NewUTXOManager(db)

	// 创建 messageManager 对象
	messageMgr, err := NewTXManager(db, utxoMgr, addrMgr)
	if err != nil {
		t.Error("can't create messageManager : ", err)
		return
	}

	pairs := make(map[string]uint64)
	pairs[""] = 1000000

	headerSizeWithoutAuthors := 4 + 1 + 32 + 32 + 8 + 1 + 64 + 1 + 1 //144bytes
	commission := uint64(headerSizeWithoutAuthors)

	assetHash, err := hex.DecodeString("8124833c6f5d1d10068b6d223c866786d49b772b12006b934a7a1e8c104f460c")
	if err != nil {
		t.Error(" can't decoded hex string .")
		return
	}
	param := utxo.PickerParam{
		Account:          addrmgr.DefaultAccountNum,
		Asset:            assetHash,
		SelectCommission: true,
	}
	msg, _, _, err := messageMgr.CreatePaymentMessage(cryptoKey, pairs, commission, param)
	if err != nil {
		t.Error(" test case : create paymnet message failed .")
		return
	}
	t.Logf(" payment message :%+v \n", msg)
	t.Log("test case : create payment message succeed .")
}

func TestMessageManager_CreateTextMessage(t *testing.T) {
	dbPath := "./~temp/TestCreateText/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testdata1, dbPath)
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
	var cryptoKey = new(addrmgr.CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		t.Error(" fetch crypto key failed .")
		return
	}

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		t.Error(" can't load secretKey from database, please retry again")
		return
	}
	var secretkey addrmgr.SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		t.Error(" test : create new secret key failed . ")
		return
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		t.Error(" can't derive secret key : ", err)
		return
	}

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		t.Error(" decrypt Cryptokey failed : ", err)
		return
	}
	copy(cryptoKey[:], cryptoKeyDec)

	keystrore := addrmgr.NewKeyStore(db, cryptoKey)

	// 创建 addressManager 对象
	addrMgr := addrmgr.NewAddressManager(keystrore, db)

	// 创建 UnspentManager 对象
	utxoMgr := utxo.NewUTXOManager(db)

	// 创建 messageManager 对象
	messageMgr, err := NewTXManager(db, utxoMgr, addrMgr)
	if err != nil {
		t.Error("can't create messageManager : ", err)
		return
	}

	msg, err := messageMgr.CreateTextMessage("this is a text message")
	if err != nil {
		t.Error(" test case : create text message failed .")
		return
	}
	t.Logf(" text message : %+v \n ", msg)
	t.Log("test case : create text message succeed .")
}

func TestMessageManager_CreateInvokeMessage(t *testing.T) {
	dbPath := "./~temp/TestCreateInvoke/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testdata1, dbPath)
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
	var cryptoKey = new(addrmgr.CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		t.Error(" fetch crypto key failed .")
		return
	}

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		t.Error(" can't load secretKey from database, please retry again")
		return
	}
	var secretkey addrmgr.SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		t.Error(" test : create new secret key failed . ")
		return
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		t.Error(" can't derive secret key : ", err)
		return
	}

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		t.Error(" decrypt Cryptokey failed : ", err)
		return
	}
	copy(cryptoKey[:], cryptoKeyDec)

	keystrore := addrmgr.NewKeyStore(db, cryptoKey)

	// 创建 addressManager 对象
	addrMgr := addrmgr.NewAddressManager(keystrore, db)

	// 创建 UnspentManager 对象
	utxoMgr := utxo.NewUTXOManager(db)

	// 创建 messageManager 对象
	messageMgr, err := NewTXManager(db, utxoMgr, addrMgr)
	if err != nil {
		t.Error("can't create messageManager : ", err)
		return
	}

	asset, err := hex.DecodeString("8124833c6f5d1d10068b6d223c866786d49b772b12006b934a7a1e8c104f460c")
	if err != nil {
		t.Error(" invalid asset id")
		return
	}
	contract, err := hex.DecodeString("766ae77cc8afba67c38aa0ba2c56db2556b33d50e64cca5846959ccedf8c7c1200")
	if err != nil {
		t.Error(" invalid contract address")
	}
	amountList := make([]uint64, 1)
	amountList[0] = uint64(10000)
	param, err := hex.DecodeString("7b0a09226f757470757473223a205b7b0a090922616d6f756e74223a203130303030352c0a090922706172616d73223a207b0a0909092261646472223a20226a62502f4d316576676941347451746162596950566830534f624c643838726b30484245726f76652f70633d220a09097d0a097d5d0a7d0a")
	if err != nil {
		t.Error("can't parse hex string ")
		return
	}
	pickParam := utxo.PickerParam{
		Account:          addrmgr.DefaultAccountNum,
		Asset:            asset,
		SelectCommission: true,
	}
	headerSizeWithoutAuthors := 4 + 1 + 32 + 32 + 8 + 1 + 64 + 1 + 1 //144bytes
	commission := uint64(headerSizeWithoutAuthors)

	args := &InvokeARGS{
		ContractAddress:contract,
		AmountList:amountList,
		Params:param,
	}

	_, msg, _, _, err := messageMgr.CreateInvokeMessage(args, cryptoKey, commission, pickParam)
	if err != nil {
		t.Error("test case :  create invoke message failed .")
		return
	}
	t.Logf(" invoke message :%+v \n", msg)
	t.Log("test case : create invoke message succeed .")
}

func TestMessageManager_CreateIssueMessage(t *testing.T) {
	dbPath := "./~temp/TestCreateIssue/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testdata1, dbPath)
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
	var cryptoKey = new(addrmgr.CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		t.Error(" fetch crypto key failed .")
		return
	}

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		t.Error(" can't load secretKey from database, please retry again")
		return
	}
	var secretkey addrmgr.SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		t.Error(" test : create new secret key failed . ")
		return
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		t.Error(" can't derive secret key : ", err)
		return
	}

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		t.Error(" decrypt Cryptokey failed : ", err)
		return
	}
	copy(cryptoKey[:], cryptoKeyDec)

	keystrore := addrmgr.NewKeyStore(db, cryptoKey)

	// 创建 addressManager 对象
	addrMgr := addrmgr.NewAddressManager(keystrore, db)

	// 创建 UnspentManager 对象
	utxoMgr := utxo.NewUTXOManager(db)

	// 创建 messageManager 对象
	messageMgr, err := NewTXManager(db, utxoMgr, addrMgr)
	if err != nil {
		t.Error("can't create messageManager : ", err)
		return
	}

	contractDefBytes, err := hex.DecodeString("1b21b88c4a4c6b943df0cb46bfe0cfdd17ee5468ca20b0f3f1dc6d6993b337c800")
	if err != nil {
		t.Error("can't decoded hex string.")
		return
	}
	contractDefs := make([]*structure.ContractDef, 1)
	contractDef := new(structure.ContractDef)
	contractDef.Deserialize(contractDefBytes)
	contractDefs[0] = contractDef

	allocationAddrs := make([]hash.HashType, 2)
	addr1, err := base64.StdEncoding.DecodeString("5AHpuNSwlH6Qoz0CDLEi6ax9YqsuTJa3A24wCbFNUdg=")
	if err != nil {
		t.Error(" can't decoded address from base64 string")
		return
	}
	allocationAddrs[0] = hash.HashType(addr1)
	addr2, err := base64.StdEncoding.DecodeString("RHQJobW4nZOzulS6tbXq6XoZR5Pwk9w2fBfBqI7IFkk=")
	if err != nil {
		t.Error(" can't decoded address from base64 string")
		return
	}
	allocationAddrs[1] = hash.HashType(addr2)

	allocationAmount := make([]int64, 2)
	allocationAmount[0] = 50000000
	allocationAmount[1] = 50000000

	addr, err := addrMgr.NewAddress("default", true)
	if err != nil {
		t.Errorf(" set publisher address failed ,can't get a new address ")
		return
	}
	allocationAddr := make([][]byte, len(allocationAddrs))
	for i, addrBytes := range allocationAddrs {
		addr := []byte(addrBytes)
		allocationAddr[i] = addr
	}

	issueArgs := &IssueARGS{
		AssetName:"USTD",
		Cap:100000000,
		FixedDenominations:false,
		Denominations:nil,
		AllocationAddr:allocationAddr,
		AllocationAmount:allocationAmount,
		PublisherAddress:addr.Address,
		Note: []byte("new test asset"),
	}

	msg, err := messageMgr.CreateIssueMessage(issueArgs)
	if err != nil {
		t.Error(" test case : create issue message failed .")
		return
	}
	t.Logf(" issue message : %+v \n", msg)
	t.Log(" test case : create issue message succeed .")
}

func TestMessageManager_CreateDeployMessage(t *testing.T) {
	dbPath := "./~temp/TestCreateDeploy/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testdata1, dbPath)
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
	var cryptoKey = new(addrmgr.CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		t.Error(" fetch crypto key failed .")
		return
	}

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		t.Error(" can't load secretKey from database, please retry again")
		return
	}
	var secretkey addrmgr.SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		t.Error(" test : create new secret key failed . ")
		return
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		t.Error(" can't derive secret key : ", err)
		return
	}

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		t.Error(" decrypt Cryptokey failed : ", err)
		return
	}
	copy(cryptoKey[:], cryptoKeyDec)

	keystrore := addrmgr.NewKeyStore(db, cryptoKey)

	// 创建 addressManager 对象
	addrMgr := addrmgr.NewAddressManager(keystrore, db)

	// 创建 UnspentManager 对象
	utxoMgr := utxo.NewUTXOManager(db)

	// 创建 messageManager 对象
	messageMgr, err := NewTXManager(db, utxoMgr, addrMgr)
	if err != nil {
		t.Error("can't create messageManager : ", err)
		return
	}

	contracts := make([][]byte, 1)
	contract1, err := hex.DecodeString("010e53696d706c65436f6e7472616374000100290a287072696e74202273696d706c6520436f6e74726163743a4f4b22290a287365747120782031290a000000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Error("can't decoded hex string")
		return
	}
	contracts[0] = contract1

	msg, err := messageMgr.CreateDeployMessage(contracts)
	if err != nil {
		t.Error(" test case : create deploy message failed .")
		return
	}
	t.Logf(" deploy message : %+v \n", msg)
	t.Log(" test case : create deploy message succeed .")
}

func TestMessageManager_ReceiveMessage(t *testing.T) {
	dbPath := "./~temp/TestReceiveMessage/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testdata2, dbPath)
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
	var cryptoKey = new(addrmgr.CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		t.Error(" fetch crypto key failed .")
		return
	}

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		t.Error(" can't load secretKey from database, please retry again")
		return
	}
	var secretkey addrmgr.SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		t.Error(" test : create new secret key failed . ")
		return
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		t.Error(" can't derive secret key : ", err)
		return
	}

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		t.Error(" decrypt Cryptokey failed : ", err)
		return
	}
	copy(cryptoKey[:], cryptoKeyDec)

	keystrore := addrmgr.NewKeyStore(db, cryptoKey)

	// 创建 addressManager 对象
	addrMgr := addrmgr.NewAddressManager(keystrore, db)

	// 创建 UnspentManager 对象
	utxoMgr := utxo.NewUTXOManager(db)

	// 创建 messageManager 对象
	messageMgr, err := NewTXManager(db, utxoMgr, addrMgr)
	if err != nil {
		t.Error("can't create messageManager : ", err)
		return
	}
	// --------------------------case 1 : receive a issue message
	recMsg0, err := hex.DecodeString("04040000000171b93bfa1e2e97d5bc7434982ead8a335e0660324398c2560ab922747a7f0a2d00035141510000000001312d00000001766ae77cc8afba67c38aa0ba2c56db2556b33d50e64cca5846959ccedf8c7c120002797685b4f6ef01d4bddeb5fa3194be8d9fe027c0265f1b395d5684a30250f0ba00000000009896802c45eaed5df3d0a78647bded3c16e2311c1f2476526f363455616b159f7c38eb00000000009896802b9004ee93c34fb3c3270d1c73a7cb11f9b2dd502ba92964b7629c942fdcdd4a0000000474657374")
	if err != nil {
		t.Error("can't decoded hex string .")
		return
	}
	message0 := msgBinaryToMessage(recMsg0)
	unit0, err := hex.DecodeString("ac2450aa6a809620511b57f14fc9211acd4026d95625f8b6695b1da84297d0f0")
	if err != nil {
		t.Error(" can't decoded hex string .")
		return
	}
	index0 := uint32(0)
	messageMgr.ReceiveMessage(message0, unit0, index0, nil)
	t.Log("test case : receive issue message succeed .")

	// --------------------------case 2 : receive a invoke message (used gravity)
	recMsg1, err := hex.DecodeString("0303000000013c022fecb15ccff38a7bb616406c5fff9369c3b0f9b38573f45651ccdee2738d8124833c6f5d1d10068b6d223c866786d49b772b12006b934a7a1e8c104f460c766ae77cc8afba67c38aa0ba2c56db2556b33d50e64cca5846959ccedf8c7c12000103beaf41c336bd7442f2a592f65e9fdcb4c21b31d13fd6429606b8c6bd209bd2430000000100000000010004616464720020e5f19c797d3699374930b4325afcf5a2db6db8555100b2af22cdeec48c7824b30200000000000186a50000010000000461646472000000202c45eaed5df3d0a78647bded3c16e2311c1f2476526f363455616b159f7c38eb0000005adbc76776690000010000000461646472000000207ce98467b64d3c05ae270a527bdcafcb9200b6fed9c69064808ccf89e91e8cab00")
	if err != nil {
		t.Error("can't decoded hex string .")
		return
	}
	message1 := msgBinaryToMessage(recMsg1)
	unit1, err := hex.DecodeString("71426d1ece4559db091c6afca93d9cec6b02aabbc3d6a0a1599e4b5fc48fa73a")
	if err != nil {
		t.Error(" can't decoded hex string .")
		return
	}
	index1 := uint32(0)
	messageMgr.ReceiveMessage(message1, unit1, index1, nil)
	t.Log("test case : receive invoke message succeed .")

	// --------------------------case 3 : receive a invoke message (used new asset)
	recMsg3, err := hex.DecodeString("030300000001d941996d8dab038c55be17fb14f69fc4790bb7efe510ec2098c4cbc3604e9ae6b2239d634ca517301cdbcf278e8235dd9726f742ee3f987a486a84271f3fef18766ae77cc8afba67c38aa0ba2c56db2556b33d50e64cca5846959ccedf8c7c12000103b2239d634ca517301cdbcf278e8235dd9726f742ee3f987a486a84271f3fef180000000000000000010004616464720020797685b4f6ef01d4bddeb5fa3194be8d9fe027c0265f1b395d5684a30250f0ba0200000000000186a50000010000000461646472000000202c45eaed5df3d0a78647bded3c16e2311c1f2476526f363455616b159f7c38eb000000000000970fdb000001000000046164647200000020c2f48fd13f2c1ce4efdb9ab81c175413fed61a25f2fd242ecb8c9b9a3d05da6100")
	if err != nil {
		t.Error("can't decoded hex string .")
		return
	}
	message3 := msgBinaryToMessage(recMsg3)
	unit3, err := hex.DecodeString("96733c89a452559cf732caa347f2eba11dcaf63c66d43a9349a7add765d5dcef")
	if err != nil {
		t.Error(" can't decoded hex string .")
		return
	}
	index3 := uint32(0)
	messageMgr.ReceiveMessage(message3, unit3, index3, nil)
	t.Log("test case : receive invoke message succeed .")

	// --------------------------case 4 : receive a payment message
	recMsg2, err := hex.DecodeString("000000000001460d7c51c2b2c7ed9826582e6c3f23916649e54384485b46f62b9bf04ecf74d18124833c6f5d1d10068b6d223c866786d49b772b12006b934a7a1e8c104f460c010000004a00ec8fdcc0ad1220949efd126424638a0bf1229388c99fdf62fe0a51aeb0f0ad20000000000000000001c12613fd9cce30c196794343d2b0d19ccb2d9085c9babfaac3c7f1eac6f9f47102000000292c45eaed5df3d0a78647bded3c16e2311c1f2476526f363455616b159f7c38eb000000000098977d000000002962ba583c07be0a1c60a84745ca006f45df05a650247e6bc0e433f2648bf9486e000000003b0291ae00")
	if err != nil {
		t.Error("can't decoded hex string .")
		return
	}
	message2 := msgBinaryToMessage(recMsg2)
	unit2, err := hex.DecodeString("38b859f7032702bb70d872bfe78461180fc5058274dfc83764b94452dc3c051e")
	if err != nil {
		t.Error(" can't decoded hex string .")
		return
	}
	index2 := uint32(0)
	messageMgr.ReceiveMessage(message2, unit2, index2, nil)
	t.Log("test case : receive payment message succeed .")

}

func TestMessageManager_UpdateMCI(t *testing.T) {
	dbPath := "./~temp/TestUpdateMCI/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testdata1, dbPath)
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
	var cryptoKey = new(addrmgr.CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		t.Error(" fetch crypto key failed .")
		return
	}

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		t.Error(" can't load secretKey from database, please retry again")
		return
	}
	var secretkey addrmgr.SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		t.Error(" test : create new secret key failed . ")
		return
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		t.Error(" can't derive secret key : ", err)
		return
	}

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		t.Error(" decrypt Cryptokey failed : ", err)
		return
	}
	copy(cryptoKey[:], cryptoKeyDec)

	keystrore := addrmgr.NewKeyStore(db, cryptoKey)

	// 创建 addressManager 对象
	addrMgr := addrmgr.NewAddressManager(keystrore, db)

	// 创建 UnspentManager 对象
	utxoMgr := utxo.NewUTXOManager(db)

	// 创建 messageManager 对象
	messageMgr, err := NewTXManager(db, utxoMgr, addrMgr)
	if err != nil {
		t.Error("can't create messageManager : ", err)
		return
	}
	db.Update(func(tx database.Tx) error {

		lastMci, _ := walletdb.DbFetchLastMci(tx)
		t.Log(" last mcu is ------ : ", lastMci)
		err := walletdb.DbPutLastMci(tx, 1519)
		if err != nil {
			return err
		}
		return nil
	})

	messages, err := hex.DecodeString("7b226d6369223a313532302c22737461626c654d65737361676573556e6974223a5b2263554a74487335465764734a4847723871543263374773437172764431714368575a354c58385350707a6f3d222c2272435251716d71416c6942524731667854386b68477331414a746c574a6669326156736471454b583050413d222c2272435251716d71416c6942524731667854386b68477331414a746c574a6669326156736471454b583050413d222c226c6e4d3869615253565a7a334d73716a522f4c726f52334b396a786d314471545361657431325856334f383d222c224f4c685a39774d6e4172747732484b2f3534526847412f4642594a30333867335a4c6c45557477384252343d225d2c22737461626c654d65737361676573223a5b2241774d414141414250414976374c46637a2f4f4b65375957514778662f354e70773744357334567a39465a527a4e3769633432424a494d38623130644541614c62534938686d6547314a74334b78494161354e4b6568364d4545394744485a7135337a497237706e773471677569785732795657737a3151356b7a4b574561566e4d37666a4877534141454476713942777a613964454c79705a4c3258702f63744d49624d64452f316b4b5742726a4776534362306b4d414141414241414141414145414247466b5a484941494f58786e486c394e706b33535443304d6c723839614c62626268565551437972794c4e3773534d6543537a41674141414141414159616c41414142414141414247466b5a484941414141674c4558713756337a304b654752373374504262694d5277664a485a53627a593056574672465a39384f4f7341414142613238646e646d6b4141414541414141455957526b63674141414342383659526e746b30384261346e436c4a37334b2f4c6b6743322f746e476b4753416a4d2b4a3652364d7177413d222c22424151414141414263626b372b6834756c395738644453594c71324b4d31344759444a446d4d4a5743726b696448702f436930414131464255514141414141424d53304141414142646d726e664d6976756d6644697143364c4662624a56617a5056446d544d7059527057637a742b4d66424941416e6c326862543237774855766436312b6a4755766f3266344366414a6c38624f563157684b4d435550433641414141414143596c6f4173526572745866505170345a4876653038467549784842386b646c4a764e6a5256595773566e33773436774141414141416d4a61414b35414537705044543750444a7730636336664c45666d793356417271536c6b74324b636c432f6333556f41414141456447567a64413d3d222c22414141414141414271527a45787756686532634b75764f62344a66614f513052504c6871384146596c686d3750463033654553424a494d38623130644541614c62534938686d6547314a74334b78494161354e4b6568364d45453947444145414141424b414c496a6e574e4d70526377484e76504a3436434e6432584a766443376a2b59656b687168436366502b385941414141415141414141414246575067356f52714c694b713855354e34473675356a516b6e6c4e7a38355878366a4e47776c764339344542414141414b5134764f494d4177374b627a74463379636d2f6b36526f38497865636e45717a6d6b476450526968566b5441414261387842364e546f41222c2241774d41414141423255475a6259327241347856766866374650616678486b4c742b2f6c454f77676d4d544c7732424f6d7561794935316a544b55584d427a627a79654f676a58646c7962335175342f6d487049616f516e487a2f7647485a7135337a497237706e773471677569785732795657737a3151356b7a4b574561566e4d37666a4877534141454473694f645930796c467a41633238386e6a6f4931335a636d39304c7550356836534771454a78382f377867414141414141414141414145414247466b5a48494149486c326862543237774855766436312b6a4755766f3266344366414a6c38624f563157684b4d435550433641674141414141414159616c41414142414141414247466b5a484941414141674c4558713756337a304b654752373374504262694d5277664a485a53627a593056574672465a39384f4f734141414141414143584439734141414541414141455957526b636741414143444339492f5250797763354f2f626d726763463151542f7459614a664c394a43374c6a4a7561505158615951413d222c2241414141414141425267313855634b79782b32594a6c67756244386a6b575a4a35554f45534674473969756238453750644e47424a494d38623130644541614c62534938686d6547314a74334b78494161354e4b6568364d45453947444145414141424b414f7950334d4374456943556e7630535a43526a6967767849704f49795a2f665976344b55613677384b3067414141414141414141414142775359542f5a7a4f4d4d475765554e44307244526e4d73746b49584a75722b71773866783673623539484543414141414b537846367531643839436e686b653937547757346a456348795232556d38324e4656686178576666446a7241414141414143596c333041414141414b574b365744774876676f63594b684852636f416230586642615a514a483572774f517a386d534c2b55687541414141414473436b613441225d2c22737461626c654d657373616765734944223a5b302c302c312c302c305d7d")
	if err != nil {
		t.Error(" can't decoded hex string .")
		return
	}
	msgs := new(proto.MsgBucket)
	err = json.Unmarshal(messages, msgs)
	if err != nil {
		t.Error(" json unmarshal failed .")
		return
	}

	stableMsgs := make([]structure.Message, 0)
	stableMsgIds := make([]uint32, 0)
	stableMsgUnits := make([]hash.HashType, 0)
	utxos := make([]structure.Utxo, 0)

	for _, msgBinary := range msgs.StableMessages {
		msg := msgBinaryToMessage(msgBinary)
		stableMsgs = append(stableMsgs, msg)
	}
	for _, utxoBinary := range msgs.FeeUTXOs {
		utxo := utxoBinaryToUTXO(utxoBinary)
		utxos = append(utxos, utxo)
	}
	for _, unitHash := range msgs.StableMessagesUnit {
		stableMsgUnits = append(stableMsgUnits, unitHash)
	}
	for _, mid := range msgs.StableMessagesID {
		stableMsgIds = append(stableMsgIds, mid)
	}

	messageMgr.UpdateMCI(msgs.Mci, stableMsgs, stableMsgUnits, stableMsgIds, utxos, msgs.Completed)
	t.Log(" test case : update mci succeed .")
}

func TestMessageManager_GetBalance(t *testing.T) {
	dbPath := "./~temp/TestGetBalance/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testdata1, dbPath)
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
	var cryptoKey = new(addrmgr.CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		t.Error(" fetch crypto key failed .")
		return
	}

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		t.Error(" can't load secretKey from database, please retry again")
		return
	}
	var secretkey addrmgr.SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		t.Error(" test : create new secret key failed . ")
		return
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		t.Error(" can't derive secret key : ", err)
		return
	}

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		t.Error(" decrypt Cryptokey failed : ", err)
		return
	}
	copy(cryptoKey[:], cryptoKeyDec)

	keystrore := addrmgr.NewKeyStore(db, cryptoKey)

	// 创建 addressManager 对象
	addrMgr := addrmgr.NewAddressManager(keystrore, db)

	// 创建 UnspentManager 对象
	utxoMgr := utxo.NewUTXOManager(db)

	// 创建 messageManager 对象
	messageMgr, err := NewTXManager(db, utxoMgr, addrMgr)
	if err != nil {
		t.Error("can't create messageManager : ", err)
		return
	}

	balance, err := messageMgr.GetBalance("default", "USDT")
	if err != nil {
		t.Error("test case : get balance failed : ", err)
		return
	}
	t.Logf(" balance : %+v \n ", balance)
	t.Log("test case : get balance succeed .")
}

func TestMessageManager_GetPaymentMessageInfo(t *testing.T) {
	dbPath := "./~temp/TestGetPaymentMessageInfo/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testdata1, dbPath)
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
	var cryptoKey = new(addrmgr.CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		t.Error(" fetch crypto key failed .")
		return
	}

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		t.Error(" can't load secretKey from database, please retry again")
		return
	}
	var secretkey addrmgr.SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		t.Error(" test : create new secret key failed . ")
		return
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		t.Error(" can't derive secret key : ", err)
		return
	}

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		t.Error(" decrypt Cryptokey failed : ", err)
		return
	}
	copy(cryptoKey[:], cryptoKeyDec)

	keystrore := addrmgr.NewKeyStore(db, cryptoKey)

	// 创建 addressManager 对象
	addrMgr := addrmgr.NewAddressManager(keystrore, db)

	// 创建 UnspentManager 对象
	utxoMgr := utxo.NewUTXOManager(db)

	// 创建 messageManager 对象
	messageMgr, err := NewTXManager(db, utxoMgr, addrMgr)
	if err != nil {
		t.Error("can't create messageManager : ", err)
		return
	}

	unit, err := hex.DecodeString("3380d4002497fec27bb54432a4ea4f9099ca4feca0e5c90f8297f1420053447b")
	index := uint32(0)
	msg, err := messageMgr.GetPaymentMessageInfo(unit, index)
	if err != nil {
		t.Error(" test case : get payment message info failed .", err)
		return
	}
	t.Logf(" message : %+v \n", msg)
	t.Log(" test case : get payment message info succeed .")
}

func TestMessageManager_RecordMessage(t *testing.T) {
	dbPath := "./~temp/TestRecordMessage/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testdata1, dbPath)
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
	var cryptoKey = new(addrmgr.CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		t.Error(" fetch crypto key failed .")
		return
	}

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		t.Error(" can't load secretKey from database, please retry again")
		return
	}
	var secretkey addrmgr.SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		t.Error(" test : create new secret key failed . ")
		return
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		t.Error(" can't derive secret key : ", err)
		return
	}

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		t.Error(" decrypt Cryptokey failed : ", err)
		return
	}
	copy(cryptoKey[:], cryptoKeyDec)

	keystrore := addrmgr.NewKeyStore(db, cryptoKey)

	// 创建 addressManager 对象
	addrMgr := addrmgr.NewAddressManager(keystrore, db)

	// 创建 UnspentManager 对象
	utxoMgr := utxo.NewUTXOManager(db)

	// 创建 messageManager 对象
	messageMgr, err := NewTXManager(db, utxoMgr, addrMgr)
	if err != nil {
		t.Error("can't create messageManager : ", err)
		return
	}

	recMsg, err := hex.DecodeString("030300000001455ca77955448b854394af8a8515e2987007eb6cf9dc9b65315ef6cc50aed91f2f3ceb826b6499c2f13043a341a703af181854a157ddd0b0797acce3ea6a75f0766ae77cc8afba67c38aa0ba2c56db2556b33d50e64cca5846959ccedf8c7c120001038dc247f0883ccddf38a23342616de6bf993824bf0875f7604d8603894562cec60000000000000001010004616464720020e8bc59c4d69c325148675194cdfb774b2568bf21788c09c3c11f1d5b10e1e6430200000000000186a50000010000000461646472000000202c45eaed5df3d0a78647bded3c16e2311c1f2476526f363455616b159f7c38eb000000000000958936000001000000046164647200000020dc6c95bef0b1bcd255c4c517a667624f3e050c3c24db30b5319157376a0688ec00")
	if err != nil {
		t.Error("can't decoded hex string .")
		return
	}
	message := msgBinaryToMessage(recMsg)
	unit, err := hex.DecodeString("d3c82405b934508d92be33935344da9b4af0dd92b622d06370427463e2f1a796")
	if err != nil {
		t.Error(" can't decoded hex string .")
		return
	}
	index := uint32(0)
	db.Update(func(tx database.Tx) error {
		timestamp := time.Now().Unix()
		err := messageMgr.RecordMessage(tx, message, unit, index, timestamp, 1483)
		if err != nil {
			t.Error("test  case : recored message failed .")
			return err
		}
		t.Log(" test case : recored message succeed .")
		return nil
	})

}

func TestMessageManager_ListMessagesHistory(t *testing.T) {
	dbPath := "./~temp/TestListMessagesHistory/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testdata1, dbPath)
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
	var cryptoKey = new(addrmgr.CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		t.Error(" fetch crypto key failed .")
		return
	}

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		t.Error(" can't load secretKey from database, please retry again")
		return
	}
	var secretkey addrmgr.SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		t.Error(" test : create new secret key failed . ")
		return
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		t.Error(" can't derive secret key : ", err)
		return
	}

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		t.Error(" decrypt Cryptokey failed : ", err)
		return
	}
	copy(cryptoKey[:], cryptoKeyDec)

	keystrore := addrmgr.NewKeyStore(db, cryptoKey)

	// 创建 addressManager 对象
	addrMgr := addrmgr.NewAddressManager(keystrore, db)

	// 创建 UnspentManager 对象
	utxoMgr := utxo.NewUTXOManager(db)

	// 创建 messageManager 对象
	messageMgr, err := NewTXManager(db, utxoMgr, addrMgr)
	if err != nil {
		t.Error("can't create messageManager : ", err)
		return
	}
	_, _, msg, err := messageMgr.ListMessagesHistory(1, 10000)
	if err != nil {
		t.Error(" test case : get payment message info failed : ", err)
		return
	}
	t.Log("message count : ", len(msg))
	t.Logf(" payment message : %+v \n", msg)
	t.Log(" test case : get payment message info succeed .")
}

func TestDeleteMessage(t *testing.T) {

	dbPath := "./~temp/TestListDeleteMessage/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testdata1, dbPath)
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

	db.Update(func(tx database.Tx) error {
		messageBucket := tx.Data().Bucket([]byte("message"))
		messageBucket.ForEach(func(k, v []byte) error {
			err := messageBucket.Delete(k)
			if err != nil {
				return err
			}
			return nil
		})

		messageIndexBucket := tx.Data().Bucket([]byte("m-index"))
		messageIndexBucket.ForEach(func(k, v []byte) error {
			err := messageIndexBucket.Delete(k)
			if err != nil {
				return err
			}
			return nil
		})

		utxoBucket := tx.Data().Bucket([]byte("utxo"))
		utxoBucket.ForEach(func(k, v []byte) error {
			err := utxoBucket.Delete(k)
			if err != nil {
				return err
			}
			return nil
		})

		if err != nil {
			t.Error("delete message failed .")
		}
		return nil
	})
}

func deCompress(zipFile, dest string) error {
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
func msgBinaryToMessage(msgBinary []byte) structure.Message {
	switch msgBinary[0] {
	case structure.PaymentMessageType:
		paymentMessage := new(structure.PaymentMessage)
		paymentMessage.Deserialize(msgBinary)
		return paymentMessage
	case structure.TextMessageType:
		textMessage := new(structure.TextMessage)
		textMessage.Deserialize(msgBinary)
		return textMessage
	case structure.KeyMessageType:
		keyMessage := new(structure.KeyMessage)
		keyMessage.Deserialize(msgBinary)
		return keyMessage
	case structure.IssueMessageType:
		issueMessage := new(structure.IssueMessage)
		issueMessage.Deserialize(msgBinary)
		return issueMessage
	case structure.InvokeMessageType:
		invokeMessage := new(structure.InvokeMessage)
		invokeMessage.Deserialize(msgBinary)
		return invokeMessage
	}
	return nil
}
func utxoBinaryToUTXO(utxoBinary []byte) structure.Utxo {
	switch utxoBinary[0] {
	case structure.TxUtxoType:
		txutxo := new(structure.TxUtxo)
		txutxo.Deserialize(utxoBinary)
		return txutxo
	case structure.CommissionUtxoType:
		commissionutxo := new(structure.CommissionUtxo)
		commissionutxo.Deserialize(utxoBinary)
		return commissionutxo
	case structure.ExternalUtxoType:
		externalutxo := new(structure.ExternalUtxo)
		externalutxo.Deserialize(utxoBinary)
		return externalutxo
	}
	return nil
}
