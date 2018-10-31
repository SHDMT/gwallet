package utxo

import (
	"archive/zip"
	"encoding/hex"
	"fmt"
	"github.com/SHDMT/gravity/platform/consensus/structure"
	"github.com/SHDMT/gwallet/infrastructure/database"
	_ "github.com/SHDMT/gwallet/infrastructure/database/badgerdb"
	"github.com/SHDMT/gwallet/platform/addrmgr"
	"github.com/SHDMT/gwallet/platform/walletdb"
	"io"
	"os"
	"strings"
	"testing"
)

const (
	dbName = "badgerDB"
	testData = "../testdata/wallet_test_data3.zip"
)

func TestNewUTXOManager(t *testing.T) {
	dbPath := "./~temp/TestNewUtxoManager/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testData, dbPath)
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
	// 创建 UnspentManager 对象
	utxoMgr := NewUTXOManager(db)
	t.Logf("UTXO manager : %+v \n ", utxoMgr)
	t.Log("test case : create new UTXO manager succeed .")
}

func TestUTXOManager_GetAmount(t *testing.T) {
	dbPath := "./~temp/TestGetAmount/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testData, dbPath)
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

	utxoMgr := NewUTXOManager(db)

	asset, err := hex.DecodeString("8124833c6f5d1d10068b6d223c866786d49b772b12006b934a7a1e8c104f460c")
	if err != nil {
		t.Error(" decoded hex string failed .")
		return
	}
	amount := utxoMgr.GetAmount(addrmgr.DefaultAccountNum, asset)
	t.Log("Amount : ", amount)
	if amount == 99900089888447 {
		t.Log(" test case : utxoManager get amount succeed .")
	} else {
		t.Error(" test case : utxoManager get amount failed .")
	}
}

func TestUTXOManager_ListUTXOsByAsset(t *testing.T) {
	dbPath := "./~temp/TestListUtxoByAsset/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testData, dbPath)
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

	utxoMgr := NewUTXOManager(db)

	asset, err := hex.DecodeString("8124833c6f5d1d10068b6d223c866786d49b772b12006b934a7a1e8c104f460c")
	if err != nil {
		t.Error(" decoded hex string failed .")
		return
	}

	utxos, err := utxoMgr.ListUTXOsByAsset(addrmgr.DefaultAccountNum, asset)
	if err != nil {
		t.Error("test case : list utxo by asset failed .")
		return
	}
	for i, utxo := range utxos {
		t.Logf("utxo %d : %+v \n ", i, utxo)
	}
	t.Log("test case : list utxo by asset succeed .")
}

func TestUTXOManager_GetUTXOInfo(t *testing.T) {
	dbPath := "./~temp/TestGetUtxoInfo/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testData, dbPath)
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
	utxoMgr := NewUTXOManager(db)

	// ------------------------case 1 : get a not exist utxo info
	utxoID, err := hex.DecodeString("ec8fdcc0ad1220949efd126424638a0bf1229388c99fdf62fe0a51aeb0f0ad200000000000000000")
	if err != nil {
		t.Error(" test case : get utxo info failed , decoded hex string failed .")
		return
	}
	utxoInfo := utxoMgr.GetUTXOInfo(addrmgr.DefaultAccountNum, utxoID)
	if utxoInfo == nil {
		t.Log(" test case : get utxo info succeed .")
	} else {
		t.Error("test case : get utxo info failed .")
	}

	// -------------------------case 2 : get a exist utxo info
	existUtxo, err := hex.DecodeString("d3c82405b934508d92be33935344da9b4af0dd92b622d06370427463e2f1a7960000000000000001")
	if err != nil {
		t.Error(" test case : get utxo info failed , decoded hex string failed .")
		return
	}
	existUtxoInfo := utxoMgr.GetUTXOInfo(addrmgr.DefaultAccountNum, existUtxo)
	if existUtxoInfo != nil {
		t.Logf(" utxo info : %+v ", existUtxoInfo)
		t.Log(" test case : get utxo info succeed .")
	} else {
		t.Error("test case : get utxo info failed .")
	}
}

func TestUTXOManager_HasUTXOInfo(t *testing.T) {
	dbPath := "./~temp/TestHasUtxoInfo/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testData, dbPath)
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
	utxoMgr := NewUTXOManager(db)

	// ---------------- case 1 : use not exist utxo id
	utxoID, err := hex.DecodeString("ec8fdcc0ad1220949efd126424638a0bf1229388c99fdf62fe0a51aeb0f0ad200000000000000000")
	if err != nil {
		t.Error(" test case : get utxo info failed , decoded hex string failed .")
		return
	}
	result := utxoMgr.HasUTXOInfo(addrmgr.DefaultAccountNum, utxoID)
	if result {
		t.Error(" test case : hash utxo info failed .")
		return
	}
	t.Log(" test case : hash utxo info succeed .")

	// ---------------- case 2 : use exist utxo id
	existUtxoID, err := hex.DecodeString("d3c82405b934508d92be33935344da9b4af0dd92b622d06370427463e2f1a7960000000000000001")
	if err != nil {
		t.Error(" test case : get utxo info failed , decoded hex string failed .")
		return
	}
	result = utxoMgr.HasUTXOInfo(addrmgr.DefaultAccountNum, existUtxoID)
	if result {
		t.Log(" test case : hash utxo info succeed .")
		return
	}
	t.Error(" test case : hash utxo info failed .")
}

func TestUTXOManager_AddNewAccount(t *testing.T) {
	dbPath := "./~temp/TestAddNewAccount/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testData, dbPath)
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
	utxoMgr := NewUTXOManager(db)

	utxoMgr.AddNewAccount(5)
	t.Log("test case : add new account to save account't utxo succeed .")
}

func TestUTXOManager_AddUTXOInfoStable(t *testing.T) {
	dbPath := "./~temp/TestAddUtxoInfoStableo/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testData, dbPath)
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
	utxoMgr := NewUTXOManager(db)

	body, err := hex.DecodeString("00ac2450aa6a809620511b57f14fc9211acd4026d95625f8b6695b1da84297d0f00000000000000000797685b4f6ef01d4bddeb5fa3194be8d9fe027c0265f1b395d5684a30250f0baac2450aa6a809620511b57f14fc9211acd4026d95625f8b6695b1da84297d0f00000000000989680ffffffffffffffff0000000001000000046164647200000020797685b4f6ef01d4bddeb5fa3194be8d9fe027c0265f1b395d5684a30250f0ba00")
	if err != nil {
		t.Error(" decoded hex string failed .")
		return
	}
	var utxo structure.TxUtxo
	utxo.Deserialize(body)

	utxoInfo := &UnspentInfo{
		Account:	addrmgr.DefaultAccountNum,
		Body:	&utxo,
	}
	err = db.Update(func(tx database.Tx) error {
		err := utxoMgr.AddUTXOInfoStable(tx,utxoInfo)
		return err
	})
	if err != nil {
		t.Error(" test case : add utxoInfo to stableUtxos failed .")
		return
	}
	t.Log(" test case : add utxoInfo to stableUtxos succeed .")
}

func TestUTXOManager_RemoveUTXOStable(t *testing.T) {
	dbPath := "./~temp/TestAddUtxoInfoStableo/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testData, dbPath)
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
	utxoMgr := NewUTXOManager(db)

	body, err := hex.DecodeString("00ac2450aa6a809620511b57f14fc9211acd4026d95625f8b6695b1da84297d0f00000000000000000797685b4f6ef01d4bddeb5fa3194be8d9fe027c0265f1b395d5684a30250f0baac2450aa6a809620511b57f14fc9211acd4026d95625f8b6695b1da84297d0f00000000000989680ffffffffffffffff0000000001000000046164647200000020797685b4f6ef01d4bddeb5fa3194be8d9fe027c0265f1b395d5684a30250f0ba00")
	if err != nil {
		t.Error(" decoded hex string failed .")
		return
	}
	var utxo structure.TxUtxo
	utxo.Deserialize(body)

	utxoInfo := &UnspentInfo{
		Account:	addrmgr.DefaultAccountNum,
		Body:	&utxo,
	}
	err = db.Update(func(tx database.Tx) error {
		err := utxoMgr.RemoveUTXOStable(tx,utxoInfo)
		return err
	})
	if err != nil {
		t.Error(" test case : remove utxoInfo from stableUtxos failed .")
		return
	}
	t.Log(" test case : remove utxoInfo from stableUtxos succeed .")
}

func TestUTXOManager_SelectInputs(t *testing.T) {
	dbPath := "./~temp/TestSelectInputs/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	deCompress(testData, dbPath)
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
	utxoMgr := NewUTXOManager(db)

	asset, err := hex.DecodeString("8124833c6f5d1d10068b6d223c866786d49b772b12006b934a7a1e8c104f460c")
	if err != nil {
		t.Error(" hex decoded failed .")
		return
	}

	param := PickerParam{
		Account:          addrmgr.DefaultAccountNum,
		Asset:            asset,
		SelectCommission: true,
	}

	result ,err := utxoMgr.SelectInputs(cryptoKey , 100005,0,param)
	if err != nil{
		t.Error("test case : select message inputs failed .")
		return
	}
	t.Logf(" select result : %+v \n ", result)
	t.Log(" test case : select message inputs succeed .")

	// ----------------- case 2:
	param2 := PickerParam{
		Account:          2,
		Asset:            asset,
		SelectCommission: true,
	}

	result2 ,err := utxoMgr.SelectInputs(cryptoKey , 10005,0,param2)
	if err != nil{
		t.Error("test case : select message inputs failed .")
		return
	}
	t.Logf(" select result : %+v \n ", result2)
	t.Log(" test case : select message inputs succeed .")
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
		filename := dest + file.Name
		err = os.MkdirAll(getDir(filename), 0755)
		if err != nil {
			return err
		}
		w, err := os.Create(filename)
		if err != nil {
			return err
		}
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
