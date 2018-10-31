package walletdb

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"reflect"
	"testing"

	"encoding/binary"
	"errors"
	gconfig "github.com/SHDMT/gravity/infrastructure/config"
	"github.com/SHDMT/gravity/infrastructure/log"
	"github.com/SHDMT/gwallet/infrastructure/database"
	_ "github.com/SHDMT/gwallet/infrastructure/database/badgerdb"
	"github.com/SHDMT/gwallet/platform/walletdb/internal/dbnamespace"
	_ "github.com/SHDMT/gwallet/platform/walletdb/internal/dbnamespace"
	"time"
)

const (
	dbName = "badgerDB"
)
const (
	checkMark = "\u2713"
	ballotX   = "\u2717"
)

func TestCreateDataseAndBuckets(t *testing.T) {

	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)

	dbPath := "./~temp/TestCreateDataseAndBuckets/"
	os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	db.View(func(tx database.Tx) error {
		lastMci, _ := DbFetchLastMci(tx)
		if lastMci == 0 {
			t.Logf("CreateBucket测试成功%v", checkMark)
		} else {
			t.Errorf("CreateBucket测试失败%v", ballotX)
		}
		return nil
	})
}

func TestKeyPairs(t *testing.T) {

	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)
	dbPath := "./~temp/TestKeyPairs/"

	os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	publicKey := []byte{158, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 78,
	}
	privateKey := []byte{158, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 88,
	}
	emptyKey := []byte{18, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 78,
	}
	err = db.Update(func(tx database.Tx) error {
		err := DbPutKeyPairs(tx, publicKey, privateKey)
		if err != nil {
			t.Fatalf("KeyPairs插入数据库出错%v", ballotX)
		}
		var queryPrivateKey []byte

		queryPrivateKey, _ = DbFetchPrivateKey(tx, emptyKey)
		if queryPrivateKey != nil {
			t.Fatalf("KeyPairs查询数据库出错%v", ballotX)
		}

		queryPrivateKey, err = DbFetchPrivateKey(tx, publicKey)
		if err != nil {
			t.Fatalf("KeyPairs查询数据库出错%v", ballotX)
		}
		//fmt.Println("privateKey:",privateKey)
		//fmt.Println("queryPrivateKey",queryPrivateKey)
		if queryPrivateKey == nil || !bytes.Equal(queryPrivateKey, privateKey) {
			t.Fatalf("KeyPairs数据库操作出错%v", ballotX)
		} else {
			t.Logf("KeyPairs测试成功%v", checkMark)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("此处测试出错%v", ballotX)
	}

}

func TestAddrPub(t *testing.T) {

	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)
	dbPath := "./~temp/TestAddrPub/"

	os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	publicKey := []byte{158, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 78,
	}

	addrHash := []byte{158, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 88,
	}

	emptyKey := []byte{18, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 78,
	}
	err = db.Update(func(tx database.Tx) error {
		err := DbPutAddrPub(tx, addrHash, publicKey)
		if err != nil {
			t.Fatalf("AddrPub插入数据库出错%v", ballotX)
		}
		var queryPublicKey []byte

		queryPublicKey, _ = DbFetchPublicKey(tx, emptyKey)
		if queryPublicKey != nil {
			t.Fatalf("AddrPub查询数据库出错%v", ballotX)
		}

		queryPublicKey, err = DbFetchPublicKey(tx, addrHash)
		if err != nil {
			t.Fatalf("AddrPub查询数据库出错%v", ballotX)
		}
		//fmt.Println("privateKey:",privateKey)
		//fmt.Println("queryPrivateKey",queryPrivateKey)
		if queryPublicKey == nil || !bytes.Equal(queryPublicKey, publicKey) {
			t.Fatalf("AddrPub数据库操作出错%v", ballotX)
		} else {
			t.Logf("AddrPub测试成功%v", checkMark)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("此处测试出错%v", ballotX)
	}

}

func TestAccount(t *testing.T) {

	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)
	dbPath := "./~temp/TestAccount/"

	os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	name := []byte("张三")
	accountIndex := uint32(0)

	err = db.Update(func(tx database.Tx) error {
		err := DbPutAccount(tx, name, accountIndex)
		if err != nil {
			t.Fatalf("Account插入数据库出错%v", ballotX)
		}
		var has bool
		has = DbHasAccount(tx, name)
		if !has {
			t.Fatalf("Account插入数据库失败%v", ballotX)
		}
		var account []byte

		account, err = DbFetchAccount(tx, name)
		if err != nil {
			t.Fatalf("查询数据库出错%v", ballotX)
		}
		if accountIndex != binary.BigEndian.Uint32(account) {
			t.Fatalf("查询数据库出错%v", ballotX)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("此处测试出错%v", ballotX)
	}

}

func TestAddress(t *testing.T) {

	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)

	dbPath := "./~temp/TestAddress/"

	os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	addrHash := []byte{158, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 78,
	}
	encodeAddr := []byte{158, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 88,
	}
	emptyKey := []byte{18, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 78,
	}
	err = db.Update(func(tx database.Tx) error {
		err := DbPutAddress(tx, addrHash, encodeAddr)
		if err != nil {
			t.Fatalf("Address插入数据库出错%v", ballotX)
		}

		var queryEncodeAddr []byte
		var queryEncodeAddrs [][]byte

		queryEncodeAddr, _ = DbFetchAddress(tx, emptyKey)
		if queryEncodeAddr != nil {
			t.Fatalf("Address查询数据库出错%v", ballotX)
		}
		//if DbIsMyAddress(tx, emptyKey) {
		//	t.Fatalf("测试出错%v", ballotX)
		//}
		//if !DbIsMyAddress(tx, addrHash) {
		//	t.Fatalf("测试出错%v", ballotX)
		//}

		err = DbPutAddress(tx, addrHash, encodeAddr)
		if err != nil {
			t.Fatalf("Address插入数据库出错%v", ballotX)
		}

		queryEncodeAddr, err = DbFetchAddress(tx, addrHash)
		if err != nil {
			t.Fatalf("Address查询数据库出错%v", ballotX)
		}

		if queryEncodeAddr == nil || !bytes.Equal(queryEncodeAddr, encodeAddr) {
			t.Fatalf("Address数据库操作出错%v", ballotX)
		} else {
			t.Logf("Address测试成功%v", checkMark)
		}
		queryEncodeAddrs, err = DbListAllMyAddress(tx)
		if queryEncodeAddrs == nil {
			t.Fatalf("list数据库出错%v", ballotX)
		} else {
			fmt.Println("queryEncodeAddrs:", queryEncodeAddrs)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("此处测试出错%v", ballotX)
	}
}

func TestRecordUpdateTime(t *testing.T) {
	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)

	dbPath := "./~temp/TestRecordUpdateTime/"

	os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}
	err = RecordUpdateTime(db)
	if err != nil {
		t.Fatalf("更新数据库出错！%s", ballotX)
	}
	err = db.View(func(tx database.Tx) error {
		if !tx.Data().KeyExists(dbnamespace.UpdateKey) {
			t.Fatalf("更新数据库出错！%s", ballotX)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("更新数据库出错！%s", ballotX)
	} else {
		t.Logf("测试成功！%s", checkMark)
	}
}

func TestLastMci(t *testing.T) {

	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)

	dbPath := "./~temp/TestLastMci/"

	os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)

	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	lastMci := uint64(2)

	err = db.Update(func(tx database.Tx) error {

		queryLastMci, err := DbFetchLastMci(tx)

		err = DbPutLastMci(tx, lastMci)
		if err != nil {
			t.Fatalf("LastMci插入数据库出错%v", ballotX)
		}

		queryLastMci, err = DbFetchLastMci(tx)

		if err != nil {
			t.Fatalf("LastMci查询数据库出错%v", ballotX)
		}

		if queryLastMci == math.MaxUint64 || lastMci != queryLastMci {
			t.Fatalf("LastMci数据库操作出错%v", ballotX)
		} else {
			t.Logf("LastMci测试成功%v", checkMark)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("此处测试出错%v", ballotX)
	}
}

func TestMasterKey(t *testing.T) {
	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)
	dbPath := "./~temp/TestMasterKey/"

	os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	masterKey := []byte{158, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 88,
	}
	masterNode := []byte{18, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 78,
	}
	err = db.Update(func(tx database.Tx) error {
		err = DbPutMasterKey(tx, masterKey, masterNode)
		if err != nil {
			t.Fatalf("插入数据库出错%v", ballotX)
		}

		getMasterNode, err := DbFetchMasterKey(tx, masterKey)
		if err != nil {
			t.Fatalf("查询数据库出错%v", ballotX)
		}
		if !bytes.Equal(getMasterNode, masterNode) {
			t.Fatalf("测试失败！%s", ballotX)
		}
		return nil

	})
	if err != nil {
		t.Fatalf("查询数据库出错%v", ballotX)
	} else {
		t.Logf("测试成功！%s", checkMark)
	}
}
func TestCryptoKey(t *testing.T) {
	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)
	dbPath := "./~temp/TestCryptoKey/"

	os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	cryptoKey := []byte{18, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 78,
	}
	err = db.Update(func(tx database.Tx) error {
		err = DbPutCryptoKey(tx, cryptoKey)
		if err != nil {
			t.Fatalf("插入数据库出错%v", ballotX)
		}

		getCryptoKey, err := DbFetchCryptoKey(tx)
		if err != nil {
			t.Fatalf("查询数据库出错%v", ballotX)
		}
		if !bytes.Equal(getCryptoKey, cryptoKey) {
			t.Fatalf("测试失败！%s", ballotX)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("查询数据库出错%v", ballotX)
	} else {
		t.Logf("测试成功！%s", checkMark)
	}

}

func TestCoinTypeKey(t *testing.T) {
	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)
	dbPath := "./~temp/TestCoinTypeKey/"

	os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}
	coinTypeName := []byte("抗量子账户")
	cryptoKey := []byte{18, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 78,
	}
	err = db.Update(func(tx database.Tx) error {
		err = DbPutCoinTypeKey(tx, coinTypeName, cryptoKey)
		if err != nil {
			t.Fatalf("插入数据库出错%v", ballotX)
		}

		getCryptoKey, err := DbFetchCoinTypeKey(tx, coinTypeName)
		if err != nil {
			t.Fatalf("查询数据库出错%v", ballotX)
		}
		if !bytes.Equal(getCryptoKey, cryptoKey) {
			t.Fatalf("测试失败！%s", ballotX)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("查询数据库出错%v", ballotX)
	} else {
		t.Logf("测试成功！%s", checkMark)
	}

}

func TestAccountInfo(t *testing.T) {
	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)
	dbPath := "./~temp/TestAccountInfo/"

	os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}
	accountIndex := uint32(0)
	accountInfo := []byte{18, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 78,
	}
	err = db.Update(func(tx database.Tx) error {
		err = DbPutAccountInfo(tx, accountIndex, accountInfo)
		if err != nil {
			t.Fatalf("插入数据库出错%v", ballotX)
		}

		getAccountInfo, err := DbFetchAccountInfo(tx, accountIndex)
		if err != nil {
			t.Fatalf("查询数据库出错%v", ballotX)
		}
		if !bytes.Equal(getAccountInfo, accountInfo) {
			t.Fatalf("测试失败！%s", ballotX)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("查询数据库出错%v", ballotX)
	} else {
		t.Logf("测试成功！%s", checkMark)
	}

}

func TestUtxo(t *testing.T) {

	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)
	dbPath := "./~temp/TestUtxo/"

	os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	utxoKey := []byte{158, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 78,
	}
	utxoKey2 := []byte{15, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 78,
	}
	utxoValue := []byte{158, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 88,
	}

	err = db.Update(func(tx database.Tx) error {

		err := DbAddUtxo(tx, utxoKey, utxoValue)
		if err != nil {
			t.Fatalf("Utxo插入数据库出错%v", ballotX)
		}
		err = DbAddUtxo(tx, utxoKey2, utxoValue)
		if err != nil {
			t.Fatalf("Utxo插入数据库出错%v", ballotX)
		}

		queryUtxoValue := tx.Data().Bucket([]byte(dbnamespace.UtxoBucket)).
			Get(utxoKey)

		if bytes.Equal(utxoValue, queryUtxoValue) {
			fmt.Println("aaaaaaaaaaaaa")
		}

		var utxoKeys, utxoValues [][]byte
		utxoKeys, utxoValues, err = DbFetchAllUtxos(tx)
		result := true
		for i, queryUtxoKey := range utxoKeys {
			if bytes.Equal(queryUtxoKey, utxoKey) {
				if bytes.Equal(utxoValues[i], utxoValue) {
					t.Logf("Utxo测试成功%v", checkMark)
					result = false
					break
				}
			}
		}
		if result {
			t.Fatalf("Utxo数据库出错%v", ballotX)
		}

		err = DbRemoveUtxo(tx, utxoKey)
		if err != nil {
			t.Fatalf("Utxo删除数据库出错%v", ballotX)
		}

		//PrintDBWithBase64(db,[]byte("utxo"))

		return nil

	})
	if err != nil {
		t.Fatalf("测试UTXO出错%v\n", ballotX)
	}

	PrintDBWithBase64(db, dbnamespace.UtxoBucket)

	os.RemoveAll(dbPath)
}

func TestMessage(t *testing.T) {

	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)
	dbPath := "./~temp/TestMessage/"

	os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	messageKeyBytes := []byte{15, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 78,
	}
	messageBytes := []byte{158, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 88,
	}
	_ = db.Update(func(tx database.Tx) error {

		err := DbPutMessage(tx, messageKeyBytes, messageBytes)
		if err != nil {
			t.Fatalf("插入数据库出错 %v\n", ballotX)
		}
		var checkMessage []byte
		checkMessage, err = DbFetchMessage(tx, messageKeyBytes)
		if err != nil {
			t.Fatalf("查询数据库出错 %v\n", ballotX)
		}
		if reflect.DeepEqual(messageBytes, checkMessage) {
			t.Logf("测试成功%v", checkMark)
		} else {
			t.Fatalf("测试出错 %v\n", ballotX)
		}

		return nil
	})

	os.RemoveAll(dbPath)

}

func TestMessageIndex(t *testing.T) {
	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)
	dbPath := "./~temp/TestMessageIndex/"

	os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}
	timestamp := time.Now().Unix()
	messageKeyBytes := []byte{15, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 78,
	}

	_ = db.Update(func(tx database.Tx) error {
		err := DbPutMessageIndex(tx, 0, timestamp, messageKeyBytes)
		if err != nil {
			t.Fatalf("插入数据库出错 %v\n", ballotX)
		}
		return nil
	})
	PrintDB(db, dbnamespace.MessageIndexBucket)
	os.RemoveAll(dbPath)
}
func TestDbGetAllMessagesInRange(t *testing.T) {
	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)
	dbPath := "./~temp/Message/"

	os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	timestamp := time.Now().Unix()

	messageKeyByte := []byte{15, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 78,
	}

	messageBytes := []byte{158, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 88,
	}

	var timestamps []int64
	var messageKeyBytes [][]byte
	var messageListBytes [][]byte
	_ = db.Update(func(tx database.Tx) error {
		err := DbPutMessageIndex(tx, 0, timestamp, messageKeyByte)
		if err != nil {
			t.Fatalf("插入数据库出错 %v\n", ballotX)
		}
		err = DbPutMessage(tx, messageKeyByte, messageBytes)
		if err != nil {
			t.Fatalf("插入数据库出错 %v\n", ballotX)
		}
		timestamps, messageKeyBytes, messageListBytes, err = DbGetAllMessagesInRange(tx, 0, 1)
		return err
	})
	fmt.Println("timestamps:", timestamps)

	fmt.Println("messageKeyBytes:", messageKeyBytes)

	fmt.Println("messageListBytes:", messageListBytes)

	PrintDB(db, dbnamespace.MessageIndexBucket)
	PrintDB(db, dbnamespace.MessageBucket)
	os.RemoveAll(dbPath)

}

func TestCreateWalletBucket(t *testing.T) {

	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)

	dbPath := "./~temp/TestCreateWalletBucket/"

	os.RemoveAll(dbPath)
	db, err := database.Create(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	err = CreateWalletBucket(db)
	if err != nil {
		fmt.Printf("Error %s\n", err)
	}

	os.RemoveAll(dbPath)
}

func createDBAndBcuket(dbPath string) {

	db, err := database.Create(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	err = CreateWalletBucket(db)
	if err != nil {
		fmt.Printf("Error %s\n", err)
	}
}

//func openDB(dbPath string) database.DB {
//
//	db, err := database.Open(dbName, dbPath, dbPath)
//	defer func() {
//		if db != nil {
//			db.Close()
//		}
//	}()
//	if err != nil {
//		fmt.Printf("Error %s\n", err)
//		return nil
//	}
//	return db
//}
func TestPrintDB(t *testing.T) {
	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)

	dbPath := "./~temp/TestAddress/"

	os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	addrHash := []byte{158, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 78,
	}
	encodeAddr := []byte{158, 98, 145, 151, 12, 180, 77, 217, 64, 8, 199, 155, 202,
		249, 216, 111, 24, 180, 180, 155, 165, 178, 160, 71, 129, 219, 113,
		153, 237, 59, 158, 88,
	}
	db.Update(func(tx database.Tx) error {
		err := DbPutAddress(tx, addrHash, encodeAddr)
		if err != nil {
			t.Fatalf("Address插入数据库出错%v", ballotX)
		}
		return nil
	})
	PrintDB(db, dbnamespace.AddressBucket)

	os.RemoveAll(dbPath)
}

func TestAccountName(t *testing.T) {

	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)
	dbPath := "./~temp/TestAccountName/"

	os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	name := []byte("张三")
	accountIndex := uint32(0)

	err = db.Update(func(tx database.Tx) error {
		err := DbPutAccountName(tx, accountIndex, name)
		if err != nil {
			t.Fatalf("AccountName插入数据库出错%v", ballotX)
		}
		var accountName []byte

		accountName, err = DbFetchAccountName(tx, accountIndex)
		if err != nil {
			t.Fatalf("查询数据库出错%v", ballotX)
		}
		if !bytes.Equal(name, accountName) {
			t.Fatalf("测试不通过%v", ballotX)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("此处测试出错%v", ballotX)
	} else {
		t.Logf("测试通过%v", checkMark)
	}

}

func TestDbFetchAllAccounts(t *testing.T) {
	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)
	dbPath := "./~temp/TestDbFetchAllAccounts/"

	os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	err = db.Update(func(tx database.Tx) error {
		accountInfo1 := []byte("accountInfo1")
		accountInfo2 := []byte("accountInfo2")
		err := DbPutAccountInfo(tx, uint32(0), accountInfo1)
		if err != nil {
			t.Fatalf("AccountName插入数据库出错%v", ballotX)
		}
		err = DbPutAccountInfo(tx, uint32(1), accountInfo2)
		if err != nil {
			t.Fatalf("AccountName插入数据库出错%v", ballotX)
		}
		accountInfos, err := DbFetchAllAccounts(tx)
		if err != nil {
			t.Fatalf("DbFetchAllAccounts查询数据库出错%v", ballotX)
		}
		accountInfoNumber := uint32(0)
		for _, accountinfo := range accountInfos {
			if bytes.Equal(accountinfo, accountInfo1) || bytes.Equal(
				accountinfo, accountInfo2) {
				accountInfoNumber++
			}
		}
		if accountInfoNumber != 2 {
			t.Fatalf("测试不通过%v", ballotX)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("此处测试出错%v", ballotX)
	} else {
		t.Logf("测试通过%v", checkMark)
	}

}

func TestLastAccount(t *testing.T) {
	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)
	dbPath := "./~temp/TestLastAccount/"

	os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	index := uint32(0)
	err = db.Update(func(tx database.Tx) error {
		err := DbPutLastAccount(tx, index)
		if err != nil {
			t.Fatalf("LastAccount插入数据库出错%v", ballotX)
		}
		lastAccount, err := DbFetchLastAccount(tx)
		if err != nil {
			t.Fatalf("LastAccount查询数据库出错%v", ballotX)
		}
		if lastAccount != index {
			t.Fatalf("测试不通过%v", ballotX)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("此处测试出错%v", ballotX)
	} else {
		t.Logf("测试通过%v", checkMark)
	}

}

func TestLastUsedAccount(t *testing.T) {
	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)
	dbPath := "./~temp/TestLastUsedAccount/"

	os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	index := uint32(0)
	err = db.Update(func(tx database.Tx) error {
		err := DbPutLastUsedAccount(tx, index)
		if err != nil {
			t.Fatalf("LastUsedAccount插入数据库出错%v", ballotX)
		}
		lastUsedAccount, err := DbFetchLastUsedAccount(tx)
		if err != nil {
			t.Fatalf("LastUsedAccount查询数据库出错%v", ballotX)
		}
		if lastUsedAccount != index {
			t.Fatalf("测试不通过%v", ballotX)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("此处测试出错%v", ballotX)
	} else {
		t.Logf("测试通过%v", checkMark)
	}
}

func TestSecretKey(t *testing.T) {
	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)
	dbPath := "./~temp/TestSecretKey/"

	os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	value := []byte("secretKeyValue")
	err = db.Update(func(tx database.Tx) error {
		err := DbPutSecretKey(tx, value)
		if err != nil {
			t.Fatalf("SecretKey插入数据库出错%v", ballotX)
		}
		secretKeyValue, err := DbFetchSecretKey(tx)
		if err != nil {
			t.Fatalf("SecretKey查询数据库出错%v", ballotX)
		}
		if !bytes.Equal(secretKeyValue, value) {
			t.Fatalf("测试不通过%v", ballotX)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("此处测试出错%v", ballotX)
	} else {
		t.Logf("测试通过%v", checkMark)
	}
}

func TestAssetName(t *testing.T) {
	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)
	dbPath := "./~temp/TestAssetName/"

	os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}
	assetNameErr := errors.New("TestAssetName ERROR")
	key := []byte("AssetNameKey")
	value := []byte("AssetNameValue")
	err = db.Update(func(tx database.Tx) error {
		err := DbPutAssetName(tx, key, value)
		if err != nil {
			t.Fatalf("AssetName插入数据库出错%v", ballotX)
			return assetNameErr
		}
		has := DbHasAssetName(tx, key)
		if !has {
			t.Fatalf("AssetName插入数据库出错%v", ballotX)
			return assetNameErr
		}
		assetNameValue, err := DbFetchAssetName(tx, key)
		if err != nil {
			t.Fatalf("AssetName查询数据库出错%v", ballotX)
			return assetNameErr
		}
		err = DbDeleteAssetName(tx, key)
		if err != nil {
			t.Fatalf("AssetName删除数据库出错%v", ballotX)
			return assetNameErr
		}

		has = DbHasAssetName(tx, key)
		if has {
			t.Fatalf("AssetName删除数据库出错%v", ballotX)
			return assetNameErr
		}

		if !bytes.Equal(assetNameValue, value) {
			t.Fatalf("测试不通过%v", ballotX)
			return assetNameErr
		}
		return nil
	})
	if err != nil {
		t.Fatalf("此处测试出错%v", ballotX)
	} else {
		t.Logf("测试通过%v", checkMark)
	}
}

func TestNameAsset(t *testing.T) {
	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)
	dbPath := "./~temp/TestNameAsset/"

	os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)
	createDBAndBcuket(dbPath)
	db, err := database.Open(dbName, dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}
	nameAssetErr := errors.New("TestNameAsset ERROR")
	key := []byte("nameAssetKey")
	value := []byte("nameAssetValue")
	err = db.Update(func(tx database.Tx) error {
		err := DbPutNameAsset(tx, key, value)
		if err != nil {
			t.Fatalf("NameAsset插入数据库出错%v", ballotX)
			return nameAssetErr
		}
		has := DbHasNameAsset(tx, key)
		if !has {
			t.Fatalf("NameAsset插入数据库出错%v", ballotX)
			return nameAssetErr
		}
		nameAssetValue, err := DbFetchNameAsset(tx, key)
		if err != nil {
			t.Fatalf("NameAsset查询数据库出错%v", ballotX)
			return nameAssetErr
		}
		err = DbDeleteNameAsset(tx, key)
		if err != nil {
			t.Fatalf("NameAsset删除数据库出错%v", ballotX)
			return nameAssetErr
		}

		has = DbHasNameAsset(tx, key)
		if has {
			t.Fatalf("AssetName删除数据库出错%v", ballotX)
			return nameAssetErr
		}

		if !bytes.Equal(nameAssetValue, value) {
			t.Fatalf("测试不通过%v", ballotX)
			return nameAssetErr
		}
		return nil
	})
	if err != nil {
		t.Fatalf("此处测试出错%v", ballotX)
	} else {
		t.Logf("测试通过%v", checkMark)
	}
}
