package badgerdb

import (
	"crypto/rand"
	"fmt"
	"testing"
	"archive/zip"
	"bytes"
	"io"
	"os"
	"strings"

	"github.com/SHDMT/gwallet/infrastructure/database"

)

func TestCreateDBDriver(t *testing.T) {

	dbPath := "./~temp/TestCreateDBDrive/"
	os.RemoveAll(dbPath)
	db, err := createDBDriver(dbPath, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		db.Close()
		os.RemoveAll(dbPath)
	}()

	key := make([][]byte, 1024)
	value := make([][]byte, 1024)
	kvMap := make(map[string][]byte)

	db.Update(func(tx database.Tx) error {
		rdBucket, err := tx.Data().CreateBucket([]byte("RandomData"))
		if err != nil {
			t.Fatal(err)
		}

		for i := 0; i < 1024; i++ {
			key[i] = make([]byte, 8)
			rand.Read(key[i])
			value[i] = make([]byte, 32)
			rand.Read(value[i])
			err := rdBucket.Put(key[i], value[i])
			if err != nil {
				return err
			}
			kvMap[string(key[i])] = value[i]
		}

		lv2Bucket, err := rdBucket.CreateBucket([]byte("level2"))
		if err != nil {
			t.Fatal(err)
		}
		lv2Bucket.Put([]byte("level"), []byte{2})
		rdBucket.Delete(key[0])
		return nil
	})

	err = db.View(func(tx database.Tx) error {
		rdBucket := tx.Data().Bucket([]byte("RandomData"))
		err := rdBucket.ForEach(func(k, v []byte) error {
			if len(v) == 2 {
				return nil
			}

			value := kvMap[string(k)]
			if !bytes.Equal(value, v) {
				return fmt.Errorf("wrong value in random bucket")
			}
			delete(kvMap, string(k))
			return nil
		})
		if err != nil {
			return err
		}

		lv2Bucket := rdBucket.Bucket([]byte("level2"))
		v := lv2Bucket.Get([]byte("level"))
		if v[0] != 2 {
			return fmt.Errorf("wrong value data in lv2 bucket")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(kvMap) != 1 || kvMap[string(key[0])] == nil {
		t.Errorf("data error in put, get and delete")
	}

}

func TestOpenDBDriver(t *testing.T) {

	dbPath := "./~temp/TestOpenDBDriver/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	DeCompress("./testdata/dbtestdata.zip", dbPath)
	db, err := openDBDriver(dbPath, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		db.Close()
		os.RemoveAll(dbPath)
	}()
	i := 0
	err = db.View(func(tx database.Tx) error {

		rdBucket := tx.Data().Bucket([]byte("RandomData"))

		err = rdBucket.ForEach(func(k, v []byte) error {
			if len(v) == 2 {
				return nil
			}

			if len(v) != 32 || len(k) != 8 {
				return fmt.Errorf("wrong data length")
			}
			i++
			return nil
		})
		if err != nil {
			return err
		}

		lv2Bucket := rdBucket.Bucket([]byte("level2"))
		v := lv2Bucket.Get([]byte("level"))
		if v[0] != 2 {
			return fmt.Errorf("wrong value data in lv2 bucket")
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if i != 1023 {
		t.Fatalf("wrong data number")
	}

}

func TestRemoveBucket(t *testing.T) {

	dbPath := "./~temp/RemoveBucket/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	DeCompress("./testdata/dbtestdata.zip", dbPath)
	db, err := openDBDriver(dbPath, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		db.Close()
		os.RemoveAll(dbPath)
	}()
	err = db.Update(func(tx database.Tx) error {
		_, err := tx.Data().CreateBucket([]byte("RandomData"))
		if err == nil {
			return fmt.Errorf("bucket already exists, but recreated")
		}

		err = tx.Data().DeleteBucket([]byte("RandomData"))
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	i := 0
	db.View(func(tx database.Tx) error {
		tx.Data().ForEach(func(k, v []byte) error {
			i++
			return nil
		})
		return nil
	})
	if i > 1 {
		t.Fatalf("failed to Remove the buckets")
	}
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

func TestDbError(t *testing.T) {
	dbPath := "./~temp/TestDbError2/"
	os.RemoveAll(dbPath)

	db, err := createDBDriver(dbPath)
	if err == nil {
		t.Fatal("Wrong parameter number, but created successfully?\n")
	}
	fmt.Println(err)
	if db != nil {
		db.Close()
	}

	os.RemoveAll(dbPath)
	db, err = createDBDriver(dbPath, 3)
	if err == nil {
		t.Fatal("Wrong parameter type, but created successfully?\n")
	}
	fmt.Println(err)
	if db != nil {
		db.Close()
	}

	os.RemoveAll(dbPath)
	db, err = createDBDriver(3, dbPath)
	if err == nil {
		t.Fatal("Wrong parameter type, but created successfully?\n")
	}
	fmt.Println(err)
	if db != nil {
		db.Close()
	}

	os.Mkdir(dbPath, 0777)
	db, err = createDBDriver(dbPath, dbPath)
	if err == nil {
		t.Fatal(fmt.Errorf("dbPath is already existed, so it should not be created successfully"))
	}
	fmt.Println(err)
	if db != nil {
		db.Close()
	}

	db, err = openDBDriver(dbPath)
	if err == nil {
		t.Fatal("Wrong parameter number, but opened successfully?\n")
	}
	fmt.Println(err)
	if db != nil {
		db.Close()
	}

	db, err = openDBDriver(dbPath, 3)
	if err == nil {
		t.Fatal("Wrong parameter type, but opened successfully?\n")
	}
	fmt.Println(err)
	if db != nil {
		db.Close()
	}

	db, err = openDBDriver(3, dbPath)
	if err == nil {
		t.Fatal("Wrong parameter type, but opened successfully?\n")
	}
	fmt.Println(err)
	if db != nil {
		db.Close()
	}

	db, err = openDBDriver(dbPath, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		db.Close()
		os.RemoveAll(dbPath)
	}()
	if !(db.Name() == "badgerDB") {
		t.Errorf("wrong db name, expected badgerDB, got %v", db.Name())
	}

}

func Test_TxCommitAndRollBack(t *testing.T) {
	dbPath := "./~temp/Test_TxCommitAndRollBack/"
	os.RemoveAll(dbPath)
	db, err := createDBDriver(dbPath, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		db.Close()
		os.RemoveAll(dbPath)
	}()

	db.Update(func(tx database.Tx) error {
		tx.Data().Put([]byte{1}, []byte{1, 1, 1})
		tx.Commit()
		tx.Data().Put([]byte{2}, []byte{2, 2, 2})
		tx.Rollback()
		tx.Data().Put([]byte{3}, []byte{3, 3, 3})
		return nil
	})

	db.View(func(tx database.Tx) error {
		if !tx.Data().KeyExists([]byte{1}) {
			return fmt.Errorf("key, value 1 must exist")
		}
		if tx.Data().KeyExists([]byte{2}) {
			return fmt.Errorf("key, value 2 should not exist")
		}
		if tx.Data().KeyExists([]byte{3}) {
			return fmt.Errorf("key, value 3 should not exist")
		}
		return nil
	})
}
