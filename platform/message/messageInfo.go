package message

import (
	"github.com/SHDMT/gravity/platform/consensus/structure"
	"github.com/SHDMT/gwallet/platform/utxo"
)

type messageInfo struct {
	msg           structure.Message
	messageID     uint32
	utxosToAdd    []*utxo.UnspentInfo
	utxosToRemove []*utxo.UnspentInfo
}
