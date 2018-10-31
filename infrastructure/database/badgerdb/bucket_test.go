package badgerdb

import (
	"os"
	"testing"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/SHDMT/gwallet/infrastructure/database"

)

func TestBucket_ForEachRange(t *testing.T) {

	dbPath := "./~temp/TestBucket_ForEachRange/"
	os.RemoveAll(dbPath)
	db, err := createDBDriver(dbPath, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		db.Close()
		os.RemoveAll(dbPath)
	}()

	err = db.Update(func(tx database.Tx) error {
		for i := 10000; i <= 20000; i++ {
			keyBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(keyBytes, uint16(i))
			valueBytes := make([]byte, 32)

			err := tx.Data().Put(keyBytes, valueBytes)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	err = db.View(func(tx database.Tx) error {

		startBytes := make([]byte, 2)
		endBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(startBytes, uint16(11000))
		binary.BigEndian.PutUint16(endBytes, uint16(12000))
		i := uint16(11000)
		tx.Data().ForEachInRange(startBytes, endBytes, func(k, v []byte) error {
			if binary.BigEndian.Uint16(k) != i {
				return fmt.Errorf("error in for each range, expected %v, got %v", i, binary.BigEndian.Uint16(k))
			}
			i++

			return nil
		})
		if i != 12001 {
			return fmt.Errorf("12000 is not visited")
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	err = db.View(func(tx database.Tx) error {

		startBytes := make([]byte, 2)
		endBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(startBytes, uint16(19500))
		binary.BigEndian.PutUint16(endBytes, uint16(21000))
		i := uint16(19500)
		tx.Data().ForEachInRange(startBytes, endBytes, func(k, v []byte) error {
			if binary.BigEndian.Uint16(k) != i {
				return fmt.Errorf("error in for each range, expected %v, got %v", i, binary.BigEndian.Uint16(k))
			}
			i++

			return nil
		})
		if i != 20001 {
			return fmt.Errorf("20000 is not visited")
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	err = db.View(func(tx database.Tx) error {

		startBytes := make([]byte, 2)
		endBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(startBytes, uint16(8500))
		binary.BigEndian.PutUint16(endBytes, uint16(11500))
		i := uint16(10000)
		tx.Data().ForEachInRange(startBytes, endBytes, func(k, v []byte) error {
			if binary.BigEndian.Uint16(k) != i {
				return fmt.Errorf("error in for each range, expected %v, got %v", i, binary.BigEndian.Uint16(k))
			}
			i++

			return nil
		})
		if i != 11501 {
			return fmt.Errorf("11500 is not visited")
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

}

func Test_CreateBucket_Concurrent(t *testing.T) {
	dbPath := "./~temp/CreateBucketShadow/"
	os.RemoveAll(dbPath)
	db, err := database.Create("badgerDB", dbPath, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		db.Close()
		os.RemoveAll(dbPath)
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		db.Update(func(tx database.Tx) error {
			tx.Data().CreateBucket([]byte("A"))
			tx.Data().CreateBucket([]byte("B"))
			tx.Data().CreateBucket([]byte("C"))
			tx.Data().CreateBucket([]byte("D"))
			return nil
		})
		wg.Done()
	}()
	go func() {
		db.Update(func(tx database.Tx) error {
			tx.Data().CreateBucket([]byte("E"))
			tx.Data().CreateBucket([]byte("F"))
			tx.Data().CreateBucket([]byte("G"))
			tx.Data().CreateBucket([]byte("H"))
			return nil
		})
		wg.Done()
	}()
	wg.Wait()

}
