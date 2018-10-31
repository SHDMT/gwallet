package badgerdb

import (
	"github.com/dgraph-io/badger"

	"github.com/SHDMT/gwallet/infrastructure/database"
)

type tx struct {
	badgerTx   *badger.Txn
	db         *db
	rootBucket *bucket
}

// Data returns the top-most bucket for all metadata storage.
//
// This function is part of the database.Tx interface implementation.
func (dbTx *tx) Data() database.Bucket {
	return dbTx.rootBucket
}

// Commit commits all changes that have been made to the root metadata bucket
// and all of its sub-buckets to the database cache which is periodically synced
// to persistent storage.
//
// This function is part of the database.Tx interface implementation.
func (dbTx *tx) Commit() error {
	return dbTx.badgerTx.Commit(nil)
}

// Rollback undoes all changes that have been made to the root bucket and all of
// its sub-buckets.
//
// This function is part of the database.Tx interface implementation.
func (dbTx *tx) Rollback() error {
	dbTx.badgerTx.Discard()
	return nil
}


