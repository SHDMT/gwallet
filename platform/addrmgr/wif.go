package addrmgr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/SHDMT/gravity/infrastructure/crypto/hash"
	"github.com/SHDMT/gravity/infrastructure/encoding/base58"
	"github.com/SHDMT/gwallet/infrastructure/config"
	"github.com/SHDMT/gwallet/infrastructure/log"
)

// ErrMalformedPrivateKey describes an error where a WIF-encoded private
// key cannot be decoded due to being improperly formatted.  This may occur
// if the byte length is incorrect or an unexpected magic number was
// encountered.
var ErrMalformedPrivateKey = errors.New("malformed private key")

// WIF contains the individual components described by the Wallet Import Format
// (WIF).  A WIF string is typically used to represent a private key and its
// associated address in a way that  may be easily copied and imported into or
// exported from wallet software.  WIF strings may be decoded into this
// structure by calling DecodeWIF or created with a user-provided private key
// by calling NewWIF.
type WIF struct {
	AlgType int
	PrivKey []byte
	netType int
}

// NewWIF creates a new WIF structure to export an address and its private key
// as a string encoded in the Wallet Import Format.  The compress argument
// specifies whether the address intended to be imported or exported was created
// by serializing the public key compressed rather than uncompressed.
func NewWIF(privKey []byte, net *config.Params, AlgType int) (*WIF, error) {
	if net == nil {
		return nil, errors.New("no network")
	}
	return &WIF{AlgType, privKey, net.NetType}, nil
}

// IsForNet returns whether or not the decoded WIF structure is associated
// with the passed network.
func (w *WIF) IsForNet(net *config.Params) bool {
	return w.netType == net.NetType
}

// String creates the Wallet Import Format string encoding of a WIF structure.
// See DecodeWIF for a detailed breakdown of the format and requirements of
// a valid WIF string.
func (w *WIF) String() string {

	encodeLen := 8 + 8 + len(w.PrivKey) + 4
	log.Debugf("your privKey is >>>:%x \n", w.PrivKey)
	a := make([]byte, encodeLen)
	binary.BigEndian.PutUint64(a[0:], uint64(w.AlgType))
	binary.BigEndian.PutUint64(a[8:], uint64(w.netType))
	copy(a[16:], w.PrivKey)
	ckSum := hash.Sum256(a[:encodeLen-4])
	copy(a[16+len(w.PrivKey):], ckSum[:4])

	return base58.Encode(a)
}

// ParseWIF parse a wif string
func (w *WIF) ParseWIF(wif string) error {

	wifBytes := base58.Decode(wif)
	len := len(wifBytes)
	algType := uint64(binary.BigEndian.Uint64(wifBytes[:8]))
	netType := uint64(binary.BigEndian.Uint64(wifBytes[8:16]))
	privKey := wifBytes[16 : len-4]
	ckSum := wifBytes[len-4:]

	checksum := hash.Sum256(wifBytes[:len-4])
	if !bytes.Equal(ckSum, checksum[:4]) {
		log.Error(" checksum missMatch ")
		return errors.New("WIF checksum missMatch")
	}

	w.AlgType = int(algType)
	w.netType = int(netType)
	w.PrivKey = privKey

	return nil
}
