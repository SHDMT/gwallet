package utxo

import (
	"github.com/SHDMT/gravity/infrastructure/crypto/hash"
	"github.com/SHDMT/gravity/platform/consensus/structure"
)

type normalUtxoList []*UnspentInfo

func (list normalUtxoList) Len() int {
	return len(list)
}

func (list normalUtxoList) Less(i, j int) bool {
	return list[i].Body.Amount() > list[j].Body.Amount()
}

func (list normalUtxoList) Swap(i, j int) {
	list[i], list[j] = list[j], list[i]
}

type commissionGroup struct {
	list      []*UnspentInfo
	allAmount uint64
}

func (group *commissionGroup) Len() int {
	return len(group.list)
}

func (group *commissionGroup) Less(i, j int) bool {
	return group.list[i].Body.(*structure.CommissionUtxo).Mci < group.list[j].Body.(*structure.CommissionUtxo).Mci
}

func (group *commissionGroup) Swap(i, j int) {
	group.list[i], group.list[j] = group.list[j], group.list[i]
}

func (group *commissionGroup) FromMci() uint64 {
	return group.list[0].Body.(*structure.CommissionUtxo).Mci
}

func (group *commissionGroup) ToMci() uint64 {
	return group.list[len(group.list)-1].Body.(*structure.CommissionUtxo).Mci
}

func (group *commissionGroup) Address() hash.HashType {
	return group.list[0].Body.(*structure.CommissionUtxo).Address()
}

func (group *commissionGroup) Amount() uint64 {
	return group.allAmount
}

type commissionUtxoList []*commissionGroup

func (list commissionUtxoList) Len() int {
	return len(list)
}

func (list commissionUtxoList) Less(i, j int) bool {
	return list[i].allAmount > list[j].allAmount
}

func (list commissionUtxoList) Swap(i, j int) {
	list[i], list[j] = list[j], list[i]
}
