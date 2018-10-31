package errors

import "fmt"

//WalletError error for wallet
type WalletError struct {
	errorCode   uint32 // Describes the kind of error
	description string // Human readable description of the issue
	err         error  // Underlying error
}

//error code about wallet
const (
	ErrNotFoundFormDB = iota
	ErrHasExist
	ErrMarshal
	ErrUnmarshal
	ErrDecrypt
	ErrEncrypt
	ErrPutDB
	ErrDeleteDB
	ErrUnlock
	ErrLocked
	ErrDumpPrivKey
	ErrRescanWallet
)

//Error error to string
func (e *WalletError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("%v, %s:\n%s", e.errorCode, e.description, e.err)
	}
	return fmt.Sprintf("%v, %s", e.errorCode, e.description)
}

//NewWalletError new wallet error
func NewWalletError(code uint32, des string, err error) *WalletError {
	return &WalletError{
		errorCode:   code,
		description: des,
		err:         err,
	}
}

//
//func IsNotFoundFormDBError(walletErr *WalletError) bool {
//	return walletErr.isErrorType(ErrNotFoundFormDB)
//}

func (e *WalletError) isErrorType(code uint32) bool {
	if e.errorCode == code {
		return true
	}
	switch e.err.(type) {
	case *WalletError:
		return e.err.(*WalletError).isErrorType(code)
	default:
		return false
	}
}
