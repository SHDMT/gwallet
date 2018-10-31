package database

import (
	"os"
	"testing"
)

func Test_ErrorType(t *testing.T) {
	dbPath := "./~temp/ErrorType/"
	os.RemoveAll(dbPath)

	db, err := Create("badgerDB", dbPath, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		db.Close()
		os.RemoveAll(dbPath)
	}()
	tx := db.Begin(true)
	_, err = tx.Data().CreateBucket([]byte("bucketA"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Data().CreateBucket([]byte("bucketA"))
	if !IsBucketAlreadyExistsError(err.(*DBError)) {
		t.Errorf("Wrong error type returned\n")
	}
	tx.Commit()
}
