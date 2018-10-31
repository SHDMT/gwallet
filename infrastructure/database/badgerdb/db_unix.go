// +build !windows

package badgerdb

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"

	"github.com/SHDMT/gwallet/infrastructure/database"

	"github.com/dgraph-io/badger"
	"github.com/dgraph-io/badger/options"
)

const (
	dbName = "badgerDB"
)

type db struct {
	engine         *badger.DB
	bucketCache    *sync.Map
	newestBucketID uint32
}

// Name returns the database driver name the current database instance was
// created with.
//
// This function is part of the database.DB interface implementation.
func (db *db) Name() string {
	return dbName
}

// View invokes the passed function in the context of a managed read-only
// transaction with the root bucket for the namespace.  Any errors returned from
// the user-supplied function are returned from this function.
//
// This function is part of the database.DB interface implementation.
func (db *db) View(fn func(tx database.Tx) error) error {
	return db.engine.View(func(tx *badger.Txn) error {
		return fn(db.PackTransaction(tx))
	})
}

// Update invokes the passed function in the context of a managed read-write
// transaction with the root bucket for the namespace.  Any errors returned from
// the user-supplied function will cause the transaction to be rolled back and
// are returned from this function.  Otherwise, the transaction is committed
// when the user-supplied function returns a nil error.
//
// This function is part of the database.DB interface implementation.
func (db *db) Update(fn func(database.Tx) error) error {
	return db.engine.Update(func(tx *badger.Txn) error {
		return fn(db.PackTransaction(tx))
	})
}

// Close cleanly shuts down the database and syncs all data.  It will block
// until all database transactions have been finalized (rolled back or
// committed).

// This function is part of the database.DB interface implementation.
func (db *db) Close() error {
	return db.engine.Close()
}

// PackTransaction packs a new tx from badger.Txn
func (db *db) PackTransaction(txn *badger.Txn) *tx {
	dbTx := &tx{
		badgerTx: txn,
		db:       db,
	}
	dbTx.rootBucket = &bucket{
		dbTx: dbTx,
		id:   rootBucketID,
	}
	return dbTx
}

func openBadgerDb(keyDir, valueDir string) (*db, error) {

	if !dbPathExists(keyDir) || !dbPathExists(valueDir) {
		return nil, database.NewDBError(database.ErrDbNotExist, "Database does not exist yet", nil)
	}

	opts := badger.DefaultOptions
	opts.Dir = keyDir
	opts.ValueDir = valueDir
	opts.Truncate = true

	opts.TableLoadingMode = options.FileIO
	opts.ValueLogLoadingMode = options.FileIO

	bdb, err := badger.Open(opts)
	if err != nil {
		return nil, database.NewDBError(database.ErrInOpenDB, "Failed to open badger db", err)
	}

	newDb := &db{
		engine:         bdb,
		bucketCache:    new(sync.Map),
		newestBucketID: 0,
	}
	err = newDb.initBucketCache()
	if err != nil {
		return nil, err
	}

	return newDb, nil
}

func createBadgerDb(keyDir, valueDir string) (*db, error) {

	if dbPathExists(keyDir) || dbPathExists(valueDir) {
		return nil, database.NewDBError(database.ErrDbAlreadyExist, "Database already exists", nil)
	}
	_ = os.MkdirAll(keyDir, 0700)
	_ = os.MkdirAll(valueDir, 0700)

	opts := badger.DefaultOptions
	opts.Dir = keyDir
	opts.ValueDir = valueDir
	opts.Truncate = true

	opts.TableLoadingMode = options.FileIO
	opts.ValueLogLoadingMode = options.FileIO

	bdb, err := badger.Open(opts)

	if err != nil {
		return nil, database.NewDBError(database.ErrInOpenDB, "Failed to open badger db", err)
	}

	newDb := &db{
		engine:         bdb,
		bucketCache:    new(sync.Map),
		newestBucketID: 0,
	}

	return newDb, nil
}

func dbPathExists(dir string) bool {
	_, err := os.Stat(dir)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return true
}

// Begin starts a transaction which is either read-only or read-write depending
// on the specified flag.  Multiple read-only transactions can be started
// simultaneously while only a single read-write transaction can be started at a
// time.  The call will block when starting a read-write transaction when one is
// already open.
//
// NOTE: The transaction must be closed by calling Rollback or Commit on it when
// it is no longer needed.  Failure to do so will result in unclaimed memory.
//
// This function is part of the database.DB interface implementation.
func (db *db) Begin(update bool) database.Tx {
	return db.PackTransaction(db.engine.NewTransaction(update))
}

func (db *db) initBucketCache() error {
	maxBucketID := uint16(0)
	err := db.Update(func(dbTx database.Tx) error {
		err := dbTx.Data().ForEach(func(k, v []byte) error {
			if len(v) != 2 {
				return nil
			}
			db.bucketCache.Store(string(k), v)
			id := binary.BigEndian.Uint16(v)
			if id > maxBucketID {
				maxBucketID = id
			}
			return nil
		})
		return err
	})

	if err != nil {
		return database.NewDBError(database.ErrInInitBucketCache, "Failed to init bucket cache", err)
	}
	db.newestBucketID = uint32(maxBucketID)
	fmt.Printf("max bucket id is %v\n", maxBucketID)
	return nil
}
