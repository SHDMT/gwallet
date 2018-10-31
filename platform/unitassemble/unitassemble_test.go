package unitassemble

import (
	"archive/zip"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/SHDMT/gravity/infrastructure/crypto/hash"
	"github.com/SHDMT/gravity/platform/consensus/genesis"
	"github.com/SHDMT/gravity/platform/consensus/structure"
	"github.com/SHDMT/gwallet/infrastructure/database"
	_ "github.com/SHDMT/gwallet/infrastructure/database/badgerdb"
	"github.com/SHDMT/gwallet/platform/addrmgr"
	"github.com/SHDMT/gwallet/platform/dag"
	"github.com/SHDMT/gwallet/platform/message"
	"github.com/SHDMT/gwallet/platform/utxo"
	"github.com/SHDMT/gwallet/platform/walletdb"
	"io"
	"os"
	"strings"
	"testing"
)

const (
	dbName = "badgerDB"
	testdata = "../testdata/wallet_test_data4.zip"
)

func TestUnitAssemble_CalculateCommission(t *testing.T) {
	dbPath := "./~temp/TestCreateUnit/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testdata, dbPath)
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

	// 创建 dagClient 对象
	dagClient := dag.NewClient(db)

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
	messageMgr, err := message.NewTXManager(db, utxoMgr, addrMgr)
	if err != nil {
		t.Error("can't create messageManager : ", err)
		return
	}

	// 创建 UnitAssemble 对象
	unitAssemble := NewUnitAssemble(db, utxoMgr, addrMgr, messageMgr, dagClient, cryptoKey)

	sendPairs := make(map[string]uint64)
	sendPairs["DQgVkerobo00hhrb6vTnGDOKxnYoX+FdZzhEZAZ+uTA="] = uint64(10000005)
	pArgs := &message.PaymentARGS{
		AccountName: "Account-2",
		SendPairs:   sendPairs,
	}

	commission, err := unitAssemble.CalculateCommission(pArgs)
	if err != nil {
		t.Error(" test case : calculate commission failed .")
		return
	}
	t.Logf("commission : %d \n", commission)
	t.Logf("test case calculate commission succeed .")
}

func TestUnitAssemble_CreateUnit(t *testing.T) {
	dbPath := "./~temp/TestCreateUnit/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testdata, dbPath)
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

	// 创建 dagClient 对象
	dagClient := dag.NewClient(db)

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
	messageMgr, err := message.NewTXManager(db, utxoMgr, addrMgr)
	if err != nil {
		t.Error("can't create messageManager : ", err)
		return
	}

	// 创建 UnitAssemble 对象
	unitAssemble := NewUnitAssemble(db, utxoMgr, addrMgr, messageMgr, dagClient, cryptoKey)

	sendPairs := make(map[string]uint64)
	sendPairs["DQgVkerobo00hhrb6vTnGDOKxnYoX+FdZzhEZAZ+uTA="] = uint64(10000005)
	pArgs := &message.PaymentARGS{
		AccountName: "Account-2",
		SendPairs:   sendPairs,
	}

	_, err = unitAssemble.CreateUnit(pArgs)
	if err != nil {
		t.Log(" test case : create unit succeed .")
		return
	}
	t.Error("test case create unit failed .")
}

func TestUnitAssemble_CreateUnit2(t *testing.T) {

	dbPath := "./~temp/TestCreateUnit/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testdata, dbPath)
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

	// 创建 dagClient 对象
	dagClient := dag.NewClient(db)

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
	messageMgr, err := message.NewTXManager(db, utxoMgr, addrMgr)
	if err != nil {
		t.Error("can't create messageManager : ", err)
		return
	}

	// 创建 UnitAssemble 对象
	unitAssemble := NewUnitAssemble(db, utxoMgr, addrMgr, messageMgr, dagClient, cryptoKey)
	t.Logf("unitassemble : %+v \n", unitAssemble)
	template := &structure.Unit{
		Version:     1,
		Alt:         1,
		LastKeyUnit: genesis.GenesisHash,
		LastBall:    genesis.GenesisBallHash,
		ParentUnits: []hash.HashType{genesis.GenesisHash},
	}
	t.Logf("temlate : %+v \n", template)

	// -------------------------------------case 1 : create payment message
	sendPairs := make(map[string]uint64)
	sendPairs["DQgVkerobo00hhrb6vTnGDOKxnYoX+FdZzhEZAZ+uTA="] = uint64(10000005)
	pArgs := &message.PaymentARGS{
		AccountName: "Account-2",
		SendPairs:   sendPairs,
	}
	pUnit, pSize, err := unitAssemble.createUnit(template, pArgs, true)
	if err != nil {
		t.Error("can't create unit for payment message")
		return
	}
	t.Logf("unit hash  : %x \n", pUnit.Hash())
	t.Logf("commission : %d \n", pSize)
	t.Log(" test case 1 : create unit succeed .")

	// -------------------------------------case 2 : create text message
	tArgs := &message.TextARGS{
		AccountName: "default",
		Text:        "test text message",
	}

	tUnit, tSize, err := unitAssemble.createUnit(template, tArgs, true)
	if err != nil {
		t.Error("can't create unit for text message")
		return
	}
	t.Logf("unit hash  : %x \n", tUnit.Hash())
	t.Logf("commission : %d \n", tSize)
	t.Log(" test case 2 : create unit succeed .")

	// -------------------------------------case 3 : create invoke message
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
	iArgs := &message.InvokeARGS{
		AccountName:     "default",
		Asset:           asset,
		ContractAddress: contract,
		AmountList:      amountList,
		Params:          param,
	}
	iUnit, iSize, err := unitAssemble.createUnit(template, iArgs, true)
	if err != nil {
		t.Error("can't create unit for invoke message")
		return
	}
	t.Logf("unit hash  : %x \n ", iUnit.Hash())
	t.Logf("commission : %d \n ", iSize)
	t.Log(" test case 3 : create unit succeed .")

	// -------------------------------------case 4 : create issue message no publisher address

	contractDefBytes, err := hex.DecodeString("1b21b88c4a4c6b943df0cb46bfe0cfdd17ee5468ca20b0f3f1dc6d6993b337c800")
	if err != nil {
		t.Error("can't decoded hex string.")
		return
	}
	contractDefs := make([]*structure.ContractDef, 1)
	contractDef := new(structure.ContractDef)
	contractDef.Deserialize(contractDefBytes)
	contractDefs[0] = contractDef

	allocationAddr := make([][]byte, 2)
	addr1, err := base64.StdEncoding.DecodeString("5AHpuNSwlH6Qoz0CDLEi6ax9YqsuTJa3A24wCbFNUdg=")
	if err != nil {
		t.Error(" can't decoded address from base64 string")
		return
	}
	allocationAddr[0] = addr1
	addr2, err := base64.StdEncoding.DecodeString("RHQJobW4nZOzulS6tbXq6XoZR5Pwk9w2fBfBqI7IFkk=")
	if err != nil {
		t.Error(" can't decoded address from base64 string")
		return
	}
	allocationAddr[1] = addr2

	allocationAmount := make([]int64, 2)
	allocationAmount[0] = 50000000
	allocationAmount[1] = 50000000

	isArgs := &message.IssueARGS{
		AccountName:        "default",
		AssetName:          "USDT",
		Cap:                100000000,
		FixedDenominations: false,
		Denominations:      nil,
		Contracts:          contractDefs,
		AllocationAddr:     allocationAddr,
		AllocationAmount:   allocationAmount,
		PublisherAddress:   nil,
		Note:               []byte("test asset"),
	}
	isUnit, isSize, err := unitAssemble.createUnit(template, isArgs, true)
	if err != nil {
		t.Error("can't create unit for issue message")
		return
	}
	t.Logf("unit hash  : %x \n ", isUnit.Hash())
	t.Logf("commission : %d \n ", isSize)
	t.Log(" test case 4 : create unit succeed .")

	// -------------------------------------case 5 : create issue message with publisher address
	pubAddr, err := base64.StdEncoding.DecodeString("DQgVkerobo00hhrb6vTnGDOKxnYoX+FdZzhEZAZ+uTA=")
	if err != nil {
		t.Error("can't decoded base64 string")
		return
	}
	isArgs.PublisherAddress = pubAddr
	isUnit, isSize, err = unitAssemble.createUnit(template, isArgs, true)
	if err != nil {
		t.Error("can't create unit for issue message")
		return
	}
	t.Logf("unit hash  : %x \n ", isUnit.Hash())
	t.Logf("commission : %d \n ", isSize)
	t.Log(" test case 5 : create unit succeed .")

	// -------------------------------------case 6 : create issue message with other address
	pubAddr2, err := base64.StdEncoding.DecodeString("dWf8tmqZp0dgDutImxLCpqC5RotRz/IZfBXIL7TcOcA=")
	if err != nil {
		t.Error("can't decoded base64 string")
		return
	}
	isArgs.PublisherAddress = pubAddr2
	_, _, err = unitAssemble.createUnit(template, isArgs, true)
	if err != nil {
		t.Log(" test case 6 : create unit succeed .")
	}

	// -------------------------------------case 6 : create deploy message
	contracts := make([][]byte, 1)
	contract1, err := hex.DecodeString("010e53696d706c65436f6e7472616374000100290a287072696e74202273696d706c6520436f6e74726163743a4f4b22290a287365747120782031290a000000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Error("can't decoded hex string")
		return
	}
	contracts[0] = contract1

	dArgs := &message.DeployARGS{
		AccountName: "default",
		Contracts:   contracts,
	}
	dUnit, dSize, err := unitAssemble.createUnit(template, dArgs, true)
	if err != nil {
		t.Error("can't create unit for deploy message")
		return
	}
	t.Logf("unit hash  : %x \n ", dUnit.Hash())
	t.Logf("commission : %d \n ", dSize)
	t.Log(" test case 6 : create unit succeed .")
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
