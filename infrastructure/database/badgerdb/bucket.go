package badgerdb

import (
	"encoding/binary"
	"bytes"
	"fmt"
	"sync/atomic"

	"github.com/dgraph-io/badger"

	"github.com/SHDMT/gwallet/infrastructure/database"
)

var (
	// rootBucketID is the ID of the top-level bucket.
	// It is the value 0 encoded as an unsigned big-endian uint16.
	rootBucketID = [2]byte{0, 0}

)

type bucket struct {
	dbTx *tx
	id   [2]byte
}

// Bucket retrieves a nested bucket with the given key.  Returns nil if
// the bucket does not exist.
//
// This function is part of the database.Bucket interface implementation.
func (b *bucket) Bucket(key []byte) database.Bucket {
	nextBucketID := []byte{0, 0}
	bCache := b.dbTx.db.bucketCache
	found := false
	if bCache != nil {
		if v, ok := bCache.Load(string(key)); ok {
			nextBucketID = v.([]byte)
			found = true
		}
	}
	if !found {
		keyNextBucket := make([]byte, len(key)+2)
		copy(keyNextBucket[0:2], b.id[:])
		copy(keyNextBucket[2:], key)
		//keyNextBucket := append(b.id[:], key...)
		valueNextBucket, err := b.dbTx.badgerTx.Get(keyNextBucket)
		if err != nil {
			return nil
		}
		nextBucketID, err = valueNextBucket.Value()
		if err != nil {
			return nil
		}
	}

	nextBucket := &bucket{
		dbTx: b.dbTx,
	}
	copy(nextBucket.id[:], nextBucketID)
	return nextBucket
}

// CreateBucket creates and returns a new nested bucket with the given key.
//
// Returns the following errors as required by the interface contract:
//   - ErrNoBucketName if the key is empty
//   - ErrBucketAlreadyExists if the bucket already exists
//   - ErrBucketNumTooBig if the limit of bucket numbers is reached
//   - ErrInUpdateNextBucket if the bucket info is written unsuccessfully
//
// This function is part of the database.Bucket interface implementation.
func (b *bucket) CreateBucket(key []byte) (database.Bucket, error) {

	if len(key) == 0 {
		return nil, database.NewDBError(database.ErrNoBucketName, "Bucket has no name", nil)
	}

	curTx := b.dbTx.badgerTx
	//keyNextBucket := append(b.id[:], key...)
	keyNextBucket := make([]byte, len(key)+2)
	copy(keyNextBucket[0:2], b.id[:])
	copy(keyNextBucket[2:], key)
	_, err := curTx.Get(keyNextBucket)
	if err == nil {
		errString := fmt.Sprintf("Bucket %s already exists", string(key))
		return nil, database.NewDBError(database.ErrBucketAlreadyExists, errString, err)
	}

	nextBucketID := make([]byte, 2)
	nextID := atomic.AddUint32(&(b.dbTx.db.newestBucketID), 1)
	if nextID >= 65536 {
		errString := fmt.Sprintf("Bucket number %v reaches the limitation of 65535", nextID)
		return nil, database.NewDBError(database.ErrBucketNumTooBig, errString, err)
	}

	binary.BigEndian.PutUint16(nextBucketID, uint16(nextID%65536))

	nextBucket := &bucket{
		dbTx: b.dbTx,
	}
	copy(nextBucket.id[:], nextBucketID)

	err = curTx.Set(keyNextBucket, nextBucketID)
	if err != nil {
		return nil, database.NewDBError(database.ErrInUpdateNextBucket, "Failed to write the next bucket id", err)
	}
	b.dbTx.db.bucketCache.Store(string(key), nextBucketID)

	fmt.Printf("Create bucket %v with id %v\n", string(keyNextBucket[2:]), nextBucketID)
	return nextBucket, nil
}


// DeleteBucket removes a nested bucket with the given key.
//
// Returns the following errors as required by the interface contract:
//   - ErrNoBucketName if the length of provided key is 0
//   - ErrBucketNotExist if the specified bucket does not exist
//   - ErrInDeleteBucket if db failed to delete the key-value pair in bucket
//   - ErrInDeleteBucketKey if db failed to delete bucket info
//
// This function is part of the database.Bucket interface implementation.
func (b *bucket) DeleteBucket(key []byte) error {

	if len(key) == 0 {
		return database.NewDBError(database.ErrNoBucketName, "Bucket has no name", nil)
	}

	curTx := b.dbTx.badgerTx
	//keyBucket := append(b.id[:], key...)
	keyBucket := make([]byte, len(key)+2)
	copy(keyBucket[0:2], b.id[:])
	copy(keyBucket[2:], key)
	valueBucket, err := curTx.Get(keyBucket)
	if err != nil {
		return database.NewDBError(database.ErrBucketNotExist, "Bucket does not exist", err)
	}
	prefix, err := valueBucket.Value()
	if err != nil {
		return database.NewDBError(database.ErrBucketNotExist, "Bucket does not exists", err)
	}

	iter := b.dbTx.badgerTx.NewIterator(badger.DefaultIteratorOptions)
	defer iter.Close()
	for iter.Seek(prefix); iter.ValidForPrefix(prefix); iter.Next() {
		err := b.dbTx.badgerTx.Delete(iter.Item().Key())
		if err != nil {
			errString := fmt.Sprintf("Failed to delete data with key %v", iter.Item().Key())
			return database.NewDBError(database.ErrInDeleteBucket, errString, err)
		}
	}

	err = curTx.Delete(keyBucket)
	if err != nil {
		errString := fmt.Sprintf("Failed to delete bucket %s", string(keyBucket))
		return database.NewDBError(database.ErrInDeleteBucketKey, errString, err)
	}

	return nil
}

// ForEach invokes the passed function with every key/value pair in the bucket.
// This does not include nested buckets or the key/value pairs within those
// nested buckets.
//
// WARNING: It is not safe to mutate data while iterating with this method.
// Doing so may cause the underlying cursor to be invalidated and return
// unexpected keys and/or values.
//
// Returns the following errors as required by the interface contract:
//   - ErrInGetValueInIteration if failed to get the value of key
//   - ErrOfUserFunction if error returned by user function fn
//
// NOTE: The values returned by this function are only valid during a
// transaction.  Attempting to access them after a transaction has ended will
// likely result in an access violation.
//
// This function is part of the database.Bucket interface implementation.
func (b *bucket) ForEach(fn func(k, v []byte) error) error {
	iter := b.dbTx.badgerTx.NewIterator(badger.DefaultIteratorOptions)
	defer iter.Close()
	for iter.Seek(b.id[:]); iter.ValidForPrefix(b.id[:]); iter.Next() {
		item := iter.Item()
		k := item.KeyCopy(nil)
		v, err := item.ValueCopy(nil)
		if err != nil {
			errString := fmt.Sprintf("Failed to get value of key %v in iteration", item.Key())
			return database.NewDBError(database.ErrInGetValueInIteration, errString, err)
		}
		err = fn(k[2:], v)
		if err != nil {
			return database.NewDBError(database.ErrOfUserFunction, "Error of user function occurs", err)
		}
	}
	return nil
}

// ForEachInRange invokes the passed function with key/value pairs in the bucket with given range.
// This does not include nested buckets or the key/value pairs within those
// nested buckets.
//
// WARNING: It is not safe to mutate data while iterating with this method.
// Doing so may cause the underlying cursor to be invalidated and return
// unexpected keys and/or values.
//
// Returns the following errors as required by the interface contract:
//   - ErrInGetValueInIteration if failed to get the value of key
//   - ErrOfUserFunction if error returned by user function fn
//
// NOTE: The values returned by this function are only valid during a
// transaction.  Attempting to access them after a transaction has ended will
// likely result in an access violation.
//
// This function is part of the database.Bucket interface implementation.
func (b *bucket) ForEachInRange(from, to []byte, fn func(k, v []byte) error) error {
	iter := b.dbTx.badgerTx.NewIterator(badger.DefaultIteratorOptions)
	defer iter.Close()
	fromKey := make([]byte, len(from)+2)
	copy(fromKey, b.id[:])
	copy(fromKey[2:], from)

	toKey := make([]byte, len(to)+2)
	copy(toKey, b.id[:])
	copy(toKey[2:], to)

	for iter.Seek(fromKey); iter.ValidForPrefix(b.id[:]); iter.Next() {
		item := iter.Item()
		k := item.KeyCopy(nil)
		if bytes.Compare(k, toKey) > 0 {
			break
		}
		v, err := item.ValueCopy(nil)
		if err != nil {
			return database.NewDBError(database.ErrInGetValueInIteration, "Error in get value", nil)
		}
		err = fn(k[2:], v)
		if err != nil {
			return database.NewDBError(database.ErrOfUserFunction, "Error of user function", err)
		}
	}
	return nil
}


// Put saves the specified key/value pair to the bucket.  Keys that do not
// already exist are added and keys that already exist are overwritten.
//
// Returns the following errors as required by the interface contract:
//   - ErrNoKey if the length of key is zero
//   - ErrInPut if error happened in setting data
//
// This function is part of the database.Bucket interface implementation.
func (b *bucket) Put(key, value []byte) error {

	if len(key) == 0 {
		return database.NewDBError(database.ErrNoKey, "No key is provided", nil)
	}
	fullKey := make([]byte, 2+len(key))
	copy(fullKey[0:2], b.id[:])
	copy(fullKey[2:], key)
	//fullKey := append(b.id[:], key...)
	err := b.dbTx.badgerTx.Set(fullKey, value)
	if err != nil {
		errString := fmt.Sprintf("Failed to put key %v and value %v", fullKey, value)
		return database.NewDBError(database.ErrInPut, errString, err)
	}
	return nil
}


// Get returns the value for the given key.  Returns nil if the key does not
// exist in this bucket.  An empty slice is returned for keys that exist but
// have no value assigned.
//
// NOTE: The value returned by this function is only valid during a transaction.
// Attempting to access it after a transaction has ended results in undefined
// behavior.  Additionally, the value must NOT be modified by the caller.
//
// This function is part of the database.Bucket interface implementation.
func (b *bucket) Get(key []byte) []byte {
	if len(key) == 0 {
		return nil
	}
	fullKey := make([]byte, 2+len(key))
	copy(fullKey[0:2], b.id[:])
	copy(fullKey[2:], key)
	//fullKey := append(b.id[:], key...)
	valueItem, err := b.dbTx.badgerTx.Get(fullKey)
	if err != nil {
		return nil
	}
	value, err := valueItem.ValueCopy(nil)
	if err != nil {
		return nil
	}
	return value
}

// KeyExists returns if the key-value pair exist.
//
// This function is part of the database.Bucket interface implementation.
func (b *bucket) KeyExists(key []byte) bool {
	if len(key) == 0 {
		return false
	}
	fullKey := make([]byte, 2+len(key))
	copy(fullKey[0:2], b.id[:])
	copy(fullKey[2:], key)
	//fullKey := append(b.id[:], key...)
	_, err := b.dbTx.badgerTx.Get(fullKey)
	if err != nil {
		return false
	}
	return true
}

// Delete removes the specified key from the bucket.  Deleting a key that does
// not exist does not return an error.
//
// Returns the following errors as required by the interface contract:
//   - ErrInDelete if db failed to delete the data
//
// This function is part of the database.Bucket interface implementation.
func (b *bucket) Delete(key []byte) error {
	if len(key) == 0 {
		return nil
	}
	fullKey := make([]byte, 2+len(key))
	copy(fullKey[0:2], b.id[:])
	copy(fullKey[2:], key)
	//fullKey := append(b.id[:], key...)
	err := b.dbTx.badgerTx.Delete(fullKey)
	if err != nil {
		errString := fmt.Sprintf("Failed to delete key %v", fullKey)
		return database.NewDBError(database.ErrInDelete, errString, err)
	}
	return nil
}


