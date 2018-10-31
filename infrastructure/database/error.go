package database

import "fmt"

// The followings are defined as err code in database
const (
	ErrDbAlreadyRegistered = iota
	ErrDbNotRegistered

	ErrNoBucketName
	ErrBucketAlreadyExists
	ErrBucketNumTooBig
	ErrNewestBucketIDNotFound
	ErrInUpdateNewestBucketID
	ErrInUpdateNextBucket
	ErrNoKey
	ErrInPut
	ErrInDelete
	ErrInDeleteBucket
	ErrBucketNotExist
	ErrInDeleteBucketKey
	ErrInGetValueInIteration
	ErrOfUserFunction
	ErrInInitBucketCache
	ErrInWriteRootBucket
	ErrInGetValue

	ErrInvalidPara
	ErrDbNotExist
	ErrDbAlreadyExist
	ErrInOpenDB
)

// DBError provides a single type for errors that can happen during database
// operation.  It is used to indicate several types of failures including errors
// with caller requests such as specifying invalid block regions or attempting
// to access data against closed database transactions, driver errors, errors
// retrieving data, and errors communicating with database servers.
//
// The caller can use type assertions to determine if an error is an Error and
// access the ErrorCode field to ascertain the specific reason for the failure.
type DBError struct {
	errorCode   uint32 // Describes the kind of error
	description string // Human readable description of the issue
	err         error  // Underlying error
}

// Error satisfies the error interface and prints errors.
func (e *DBError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("\n%v, %s:\n %s", e.errorCode, e.description, e.err)
	}
	return fmt.Sprintf("%v, %s", e.errorCode, e.description)
}

// NewDBError creates a new DBError with error code, err String and an inner error
func NewDBError(code uint32, des string, err error) *DBError {
	return &DBError{
		errorCode:   code,
		description: des,
		err:         err,
	}
}

// IsBucketAlreadyExistsError judges if the error code is ErrBucketAlreadyExists
// the result will be true as long as the error itself or the inner error has the specified error code
func IsBucketAlreadyExistsError(e *DBError) bool {
	return e.isErrorType(ErrBucketAlreadyExists)
}


// isErrorType decides if the error has the given error code
// since DBError has a inner error field, so as long as as long as the error itself
// or the inner error has the specified error code, the result will be true
func (e *DBError) isErrorType(code uint32) bool {
	if e.errorCode == code {
		return true
	}
	switch e.err.(type) {
	case *DBError:
		return e.err.(*DBError).isErrorType(code)
	default:
		return false
	}
}
