package errors

import (
	"fmt"
	"github.com/pkg/errors"
	"testing"
)

func TestNewWalletErrorAndError(t *testing.T) {
	wallet := NewWalletError(0, "test", errors.New("newWalletErr"))
	fmt.Println(wallet.Error())

}
func TestNewWalletErrorAndError1(t *testing.T) {
	wallet := NewWalletError(0, "test", nil)
	fmt.Println(wallet.Error())

}

func TestIsErrorType(t *testing.T) {
	wallet0 := NewWalletError(1, "test", errors.New("newWalletErr"))
	wallet := NewWalletError(0, "test", wallet0)
	fmt.Println(wallet.isErrorType(0))
}

func TestIsErrorType1(t *testing.T) {
	wallet0 := NewWalletError(1, "test", errors.New("newWalletErr"))
	wallet := NewWalletError(0, "test", wallet0)
	fmt.Println(wallet.isErrorType(1))
}

func TestIsErrorType2(t *testing.T) {
	wallet1 := NewWalletError(0, "test", errors.New("newWalletErr"))

	fmt.Println(wallet1.isErrorType(1))
}
