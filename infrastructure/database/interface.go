package database


// DB provides a generic interface that is used to store blocks and related
// metadata.  This interface is intended to be agnostic to the actual mechanism
// used for backend data storage.  The RegisterDriver function can be used to
// add a new backend data storage method.
//
// This interface is divided into two distinct categories of functionality.
//
// The first category is atomic metadata storage with bucket support.  This is
// accomplished through the use of database transactions.
//
// The second category is generic block storage.  This functionality is
// intentionally separate because the mechanism used for block storage may or
// may not be the same mechanism used for metadata storage.  For example, it is
// often more efficient to store the block data as flat files while the metadata
// is kept in a database.  However, this interface aims to be generic enough to
// support blocks in the database too, if needed by a particular backend.
type DB interface {
	// Name returns the database driver type the current database instance
	// was created with.
	Name() string
	// View invokes the passed function in the context of a managed
	// read-only transaction.  Any errors returned from the user-supplied
	// function are returned from this function.
	//
	// Calling Rollback or Commit on the transaction passed to the
	// user-supplied function will result in a panic.
	Begin(writable bool) Tx

	View(fn func(tx Tx) error) error

	// Update invokes the passed function in the context of a managed
	// read-write transaction.  Any errors returned from the user-supplied
	// function will cause the transaction to be rolled back and are
	// returned from this function.  Otherwise, the transaction is committed
	// when the user-supplied function returns a nil error.
	//
	// Calling Rollback or Commit on the transaction passed to the
	// user-supplied function will result in a panic.
	Update(fn func(tx Tx) error) error

	// Close cleanly shuts down the database and syncs all data.  It will
	// block until all database transactions have been finalized (rolled
	// back or committed).
	Close() error
}


// Tx represents a database transaction.  It can either by read-only or
// read-write.  The transaction provides a metadata bucket against which all
// read and writes occur.
//
// As would be expected with a transaction, no changes will be saved to the
// database until it has been committed.  The transaction will only provide a
// view of the database at the time it was created.  Transactions should not be
// long running operations.
type Tx interface {
	// Data returns the root bucket for all data storage.
	Data() Bucket

	// Commit commits all changes that have been made. Depending on the
	// backend implementation this could be to a cache that is periodically
	// synced to persistent storage or directly to persistent storage.
	// In any case, all transactions which are started after the commit finishes
	// will include all changes made by this transaction.
	// Calling this function on a managed transaction will result in a panic.
	Commit() error

	// Rollback undoes all changes that have been made.
	Rollback() error
}

// Bucket represents a collection of key/value pairs.
type Bucket interface {
	// Bucket retrieves a nested bucket with the given key.  Returns nil if
	// the bucket does not exist.
	Bucket(key []byte) Bucket

	// CreateBucket creates and returns a new nested bucket with the given
	// key.
	//
	// The interface contract guarantees at least the following errors will
	// be returned (other implementation-specific errors are possible):
	//   - ErrBucketExists if the bucket already exists
	//   - ErrBucketNameRequired if the key is empty
	//   - ErrIncompatibleValue if the key is otherwise invalid for the
	//     particular implementation
	//   - ErrTxNotWritable if attempted against a read-only transaction
	//   - ErrTxClosed if the transaction has already been closed
	CreateBucket(key []byte) (Bucket, error)

	// DeleteBucket removes a nested bucket with the given key.  This also
	// includes removing all nested buckets and keys under the bucket being
	// deleted.
	//
	// The interface contract guarantees at least the following errors will
	// be returned (other implementation-specific errors are possible):
	//   - ErrBucketNotFound if the specified bucket does not exist
	//   - ErrTxNotWritable if attempted against a read-only transaction
	//   - ErrTxClosed if the transaction has already been closed
	DeleteBucket(key []byte) error

	// ForEach invokes the passed function with every key/value pair in the
	// bucket.  This does not include nested buckets or the key/value pairs
	// within those nested buckets.
	//
	// WARNING: It is not safe to mutate data while iterating with this
	// method.  Doing so may cause the underlying cursor to be invalidated
	// and return unexpected keys and/or values.
	//
	// The interface contract guarantees at least the following errors will
	// be returned (other implementation-specific errors are possible):
	//   - ErrTxClosed if the transaction has already been closed
	//
	// NOTE: The slices returned by this function are only valid during a
	// transaction.  Attempting to access them after a transaction has ended
	// results in undefined behavior.  Additionally, the slices must NOT
	// be modified by the caller.  These constraints prevent additional data
	// copies and allows support for memory-mapped database implementations.
	ForEach(fn func(k, v []byte) error) error
	ForEachInRange(from, to []byte, fn func(k, v []byte) error) error
	// Put saves the specified key/value pair to the bucket.  Keys that do
	// not already exist are added and keys that already exist are
	// overwritten.
	//
	// The interface contract guarantees at least the following errors will
	// be returned (other implementation-specific errors are possible):
	//   - ErrKeyRequired if the key is empty
	//   - ErrIncompatibleValue if the key is the same as an existing bucket
	//   - ErrTxNotWritable if attempted against a read-only transaction
	//   - ErrTxClosed if the transaction has already been closed
	//
	// NOTE: The slices passed to this function must NOT be modified by the
	// caller.  This constraint prevents the requirement for additional data
	// copies and allows support for memory-mapped database implementations.
	Put(key, value []byte) error

	// Get returns the value for the given key.  Returns nil if the key does
	// not exist in this bucket.  An empty slice is returned for keys that
	// exist but have no value assigned.
	//
	// NOTE: The value returned by this function is only valid during a
	// transaction.  Attempting to access it after a transaction has ended
	// results in undefined behavior.  Additionally, the value must NOT
	// be modified by the caller.  These constraints prevent additional data
	// copies and allows support for memory-mapped database implementations.
	Get(key []byte) []byte

	// KeyExits returns if there is a key/vlue pair for the given key.
	// Returns false if the key does not exist in this bucket.
	//
	// NOTE: The value returned by this function is only a bool data to describe
	// whether the key/value pair exists. The value of key/value pair would not be accessible.
	// Use Get instead if the value is needed
	KeyExists(key []byte) bool

	// Delete removes the specified key from the bucket.  Deleting a key
	// that does not exist does not return an error.
	//
	// The interface contract guarantees at least the following errors will
	// be returned (other implementation-specific errors are possible):
	//   - ErrKeyRequired if the key is empty
	//   - ErrIncompatibleValue if the key is the same as an existing bucket
	//   - ErrTxNotWritable if attempted against a read-only transaction
	//   - ErrTxClosed if the transaction has already been closed
	Delete(key []byte) error
}
