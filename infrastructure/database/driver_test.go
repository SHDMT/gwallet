package database_test

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/SHDMT/gwallet/infrastructure/database"
	_ "github.com/SHDMT/gwallet/infrastructure/database/badgerdb"

)

func TestDbError(t *testing.T) {
	dbPath := "./~temp/TestDbError/"
	db, err := database.Create("levelDB", dbPath, dbPath)
	if err == nil {
		t.Fatal(fmt.Errorf("Level db is not registered, but created successfully?\n"))
	}
	fmt.Println(err)
	if db != nil {
		db.Close()
	}

	db, err = database.Open("levelDB", dbPath, dbPath)
	if err == nil {
		t.Fatal(fmt.Errorf("Level db is not registered, but created successfully?\n"))
	}
	fmt.Println(err)
	if db != nil {
		db.Close()
	}

	os.RemoveAll(dbPath)
	db, err = database.Open("badgerDB", dbPath, dbPath)
	if err == nil {
		t.Fatal(fmt.Errorf("dbPath does not existed, so it should not be opened successfully\n"))
	}
	fmt.Println(err)
	if db != nil {
		db.Close()
	}

	os.Mkdir(dbPath, 0777)
	db, err = database.Create("badgerDB", dbPath, dbPath)

	if err == nil {
		t.Fatal(fmt.Errorf("dbPath is already existed, so it should not be created successfully\n"))
	}
	fmt.Println(err)
	if db != nil {
		db.Close()
	}

	if len(database.DbList()) != 1 {
		t.Fatal(fmt.Errorf("Wrong db list length\n"))
	}
	if database.DbList()[0] != "badgerDB" {
		t.Fatal(fmt.Errorf("Wrong db name\n"))
	}

	driver := database.Driver{
		DbName: "badgerDB",
		Create: nil,
		Open:   nil,
	}
	err = database.RegisterDriver(driver)
	if err == nil {
		t.Fatal(fmt.Errorf("badgerdb registered twice successfully\n"))
	}

	dbErr := database.NewDBError(database.ErrBucketAlreadyExists, "Err in database", fmt.Errorf("Err in string\n"))
	errString := dbErr.Error()
	if !strings.Contains(errString, "Err in string") {
		t.Fatal(fmt.Errorf("Err info lost\n"))
	}
	if !strings.Contains(errString, "Err in database") {
		t.Fatal(fmt.Errorf("Err info lost\n"))
	}
	os.RemoveAll(dbPath)
}

func TestCreate(t *testing.T) {
	dbPath := "./~temp/TestCreate/"
	os.RemoveAll(dbPath)
	db, err := database.Create("badgerDB", dbPath, dbPath)
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
				return fmt.Errorf("Wrong value in random bucket\n")
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
			return fmt.Errorf("Wrong value data in lv2 bucket\n")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(kvMap) != 1 || kvMap[string(key[0])] == nil {
		t.Errorf("Data error in put, get and delete\n")
	}
}

func TestOpen(t *testing.T) {
	dbPath := "./~temp/TestOpen/"
	os.RemoveAll(dbPath)
	os.Mkdir(dbPath, 0777)
	DeCompress("./testdata/dbtestdata.zip", dbPath)
	db, err := database.Open("badgerDB", dbPath, dbPath)
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

		err := rdBucket.ForEach(func(k, v []byte) error {
			if len(v) == 2 {
				return nil
			}

			if len(v) != 32 || len(k) != 8 {
				return fmt.Errorf("Wrong data length\n")
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
			return fmt.Errorf("Wrong value data in lv2 bucket\n")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if i != 1023 {
		t.Fatalf("Wrong data number\n")
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
