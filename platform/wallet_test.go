package platform

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SHDMT/gwallet/infrastructure/config"
	"github.com/SHDMT/gwallet/infrastructure/log"
	_ "github.com/SHDMT/gwallet/infrastructure/database/badgerdb"
	"github.com/SHDMT/gwallet/platform/walletseed"
)

const(
	testdata = "./testdata/wallet_test_data.zip"
)
func TestNewWallet(t *testing.T) {
	log.Init(config.Parameters.MaxLogSize, config.Parameters.LogLevel, log.Stdout)

	dbfile := filepath.Join(config.Parameters.DataDir, "testnewwallet")
	db, err := CreateWalletDb(dbfile)
	if err != nil {
		t.Error(" create new wallet database failed : ", err)
		return
	}
	password := []byte("123")
	wallet, err := NewWallet(config.Parameters, db, password)
	t.Logf(" wallet : %+v", wallet)
	db.Close()
	removePath(dbfile)
}

func TestCreateWalletDb(t *testing.T) {
	log.Init(config.Parameters.MaxLogSize, config.Parameters.LogLevel, log.Stdout)

	dbfile := filepath.Join(config.Parameters.DataDir, "testcreatedb2")
	os.RemoveAll(dbfile)

	db, err := CreateWalletDb(dbfile)
	defer func() {
		db.Close()
		removePath(dbfile)
	}()
	if err != nil {
		t.Error(" create new wallet database failed : ", err)
		return
	}
	t.Logf(" new wallet database created. db : %+v", db)
	fileInfo, err := os.Stat(dbfile)
	if err != nil {
		t.Error(" Failed to get fileInfo : ", err)
		return
	}
	if fileInfo != nil && db != nil {
		t.Log("测试通过！！")
	}
}

func TestCreateWallet(t *testing.T) {
	log.Init(config.Parameters.MaxLogSize, config.Parameters.LogLevel, log.Stdout)

	dbfile := filepath.Join(config.Parameters.DataDir, "tempdata")
	removePath(dbfile)
	defer removePath(dbfile)
	password := []byte("123")
	seed := []byte("42d6eb0a8824180b3d95ba840c4ff3a8ba44145ca313d0c3d398d97fc1cafe61")
	wallet, err := CreateWallet(dbfile, password, seed)
	if err != nil {
		t.Error(" create wallet failed : ", err)
		return
	}
	if len(wallet) != 0 {
		t.Log("测试通过！")
	} else {
		t.Error("测试不通过！")
	}

}

func TestWallet_DumpPrivKey(t *testing.T) {

	dbPath := "./~temp/TestDumpPrivatekey/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	DeCompress(testdata, dbPath)
	wallet, err := OpenWallet(dbPath, []byte("flq"))
	if err != nil {
		t.Error(" can't open wallet")
		return
	}

	address, err := wallet.Addrmgr.CreateNewAddress(1, false)
	if err != nil {
		t.Error("can't get new address.")
		wallet.Stop()
		return
	}
	addrStr := base64.StdEncoding.EncodeToString(address.Address)
	t.Log("address : ", addrStr)
	wif, err := wallet.DumpPrivateKey(addrStr)
	if err != nil {
		t.Error(" can't dump privatekey .")
		wallet.Stop()
		return
	}
	t.Log(" wif private key is : ", wif)
	t.Log(" test dump privatekey succeed .")
}

func TestWallet_ImportPrivKey(t *testing.T) {

	dbPath := "./~temp/TestImportPrivate/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	DeCompress( testdata, dbPath)

	importAddress := "s9kyQVdVBQ32xyiivZiblo2BHvSFZ0ijYTWtaCYtjd4="
	wallet, err := OpenWallet(dbPath, []byte("flq"))
	if err != nil {
		t.Error(" can't open wallet")
		return
	}
	address, err := wallet.ImportPrivKey("11111112SEe6qhJ11bboJPH8HNUxaDY4j2vF3LDGDriyn2HXJ1WevEBRFN82khKEvGDk")
	if err != nil {
		t.Error("case 1(correct wif privatekey) : can't import a privatekey.")
		wallet.Stop()
		return
	}
	t.Log(" case 1 import address is : ", address)
	if address == importAddress {
		t.Log("case 1(correct wif privatekey) : import wif privatekey succeed.")
	}

	_, err = wallet.ImportPrivKey("11111112SEe6qhJ11bboJPH8HNUxaDYth2vF3LDGDriyn2HXJ1WevEBRFN82khKEvGDk")
	if err != nil {
		t.Log("case 2(incorrect wif privatekey) : mport wif privatekey succeed .")
		wallet.Stop()
		return
	}

}

func TestWallet_UpdatePassword(t *testing.T) {

	dbPath := "./~temp/TestChangePassword/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	DeCompress(testdata, dbPath)

	wallet, err := OpenWallet(dbPath, []byte("flq"))
	if err != nil {
		t.Error(" can't open wallet")
		return
	}

	err = wallet.UpdatePassword("flq", "123")
	if err != nil {
		t.Error("case 1(correct password): change wallet password failed .")
		wallet.Stop()
		return
	}
	t.Log("case 1(correct password): change wallet password succeed.")

	err = wallet.UpdatePassword("flq", "123")
	if err != nil {
		t.Log("case 2(incorrect password): change wallet password succeed.")
		wallet.Stop()
		return
	}
	t.Error("case 2(incorrect password): change wallet password failed .")
	wallet.Stop()

}

func TestWallet_Rescan(t *testing.T) {

}

func TestWallet_Lock(t *testing.T) {
	dbPath := "./~temp/TestLock/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	DeCompress(testdata, dbPath)
	wallet, err := OpenWallet(dbPath, []byte("flq"))
	if err != nil {
		t.Error(" can't open wallet")
		return
	}
	wallet.Lock()
	if bytes.Equal(wallet.CryptoKey.Bytes(), make([]byte, 32)) {
		t.Log("测试通过！")
	} else {
		t.Error("测试不通过！")
	}
	wallet.Stop()
}

func TestWallet_Unlock(t *testing.T) {
	log.Init(config.Parameters.MaxLogSize, config.Parameters.LogLevel, log.Stdout)
	dbPath := "./~temp/TestUnlock/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	DeCompress(testdata, dbPath)
	wallet, err := OpenWallet(dbPath, []byte("flq"))
	if err != nil {
		t.Error(" can't open wallet")
		return
	}
	err = wallet.Unlock("flq")
	if err != nil {
		t.Error("case 1 (correct password) : unlock wallet failed .")
	}
	t.Log("case 1 (correct password) : unlock wallet succeed .")

	err = wallet.Unlock("123")
	if err != nil {
		t.Log("case 2 (incorrect password) : test unlock wallet succeed .")
		wallet.Stop()
		return
	}
	t.Error("case 2 (incorrect password) : test unlock wallet failed .")
	wallet.Stop()
}

func TestCreateSeed(t *testing.T) {

	var seedStrSplit []string
	var err error
	_, seedStrSplit, err = walletseed.SeedGenerator()
	if err != nil {
		fmt.Println("hahahh")
		fmt.Println("err:", err)
	} else {
		fmt.Println("1234567890-")
		fmt.Println("seed:", seedStrSplit)
	}

}

func removePath(path string) error {
	err := os.RemoveAll(path)
	if err != nil {
		fmt.Println("delet dir error:", err)
		return err
	}
	return nil
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
