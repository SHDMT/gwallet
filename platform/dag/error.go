package dag

import (
	"errors"
)

// ErrClientClosed Wallet Client hasn't connected
var (
	ErrClientClosed = errors.New("wallet Client hasn't connected")
)
