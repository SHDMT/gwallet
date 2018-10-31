package utxo

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/SHDMT/crypto/bliss"
	"github.com/SHDMT/crypto/asymmetric"
	"github.com/SHDMT/crypto/secp256k1"
	"github.com/SHDMT/gravity/infrastructure/crypto/hash"
	"github.com/SHDMT/gravity/platform/consensus/genesis"
	"github.com/SHDMT/gravity/platform/consensus/structure"
	"github.com/SHDMT/gwallet/infrastructure/database"
	"github.com/SHDMT/gwallet/infrastructure/log"
	"github.com/SHDMT/gwallet/platform/addrmgr"
	"github.com/SHDMT/gwallet/platform/walletdb"
	"sort"
)

// const for calculate commission
const (
	BlissAuthorBytes = 894
	Secp256k1AuthorBytes = 182
	BlissSignBytes = 432
	Secp256k1SignBytes = 72
)

// Err error used in this file
var (
	ErrLoadAssetList = errors.New("can't fetch assetList from db")
	ErrDecryptPrivateKey = errors.New("can't decrypt account privateKey")
	ErrUnmarshalPrivateKey =  errors.New("can't unmarshal account privateKey")

	ErrNoEnoughFunds	= errors.New("no enough bytes")
	ErrLoadAllUTXO		= errors.New("failed to load utxos from db")
	ErrLoadLastUsedAccount = errors.New("failed to load last used account from db")
	ErrFetchPrivateKeyByAddress = errors.New("can't get private key of address")
)

// PickerParam UTXO selection strategy
type PickerParam struct {
	Account          uint32
	Asset            []byte
	SelectCommission bool
	ExcludedUTXO     []*UnspentInfo
	ExcludedAddress  []hash.HashType
}

// UnspentInfo UTXO information
type UnspentInfo struct {
	Account uint32
	Body    structure.Utxo
}

// UnspentCollection all the information needed to support UnspentCollection
type UnspentCollection struct {
	txUtxos *list.List
	cmUtxos *list.List
	exUtxos *list.List
	otherAssets map[hash.HashTypeS]*list.List
	utxoIndex map[string]*list.Element
}

// SelectResult UTXO select result
type SelectResult struct {
	Utxos        []*UnspentInfo
	CmGroups     []*commissionGroup
	PrivateKeys  []asymmetric.PrivateKey
	Addresses    []hash.HashType
	InputAmounts uint64
	Commission   uint64
}

// Init UnspentCollection
func (uc *UnspentCollection) Init() {
	uc.txUtxos = list.New()
	uc.cmUtxos = list.New()
	uc.exUtxos = list.New()
	uc.otherAssets = make(map[hash.HashTypeS]*list.List)
	uc.utxoIndex = make(map[string]*list.Element)
}

// UnspentManager all the information needed to support UnspentManager
type UnspentManager struct {
	db    database.DB
	utxos []*UnspentCollection
}

// NewUTXOManager create a new UnspentManager instance
func NewUTXOManager(db database.DB) *UnspentManager {
	utxoMgr := &UnspentManager{
		db: db,
	}
	utxoMgr.LoadAllUTXOsFromDb()
	return utxoMgr
}

// GetAmount calculate amount of specified account , asset
func (um *UnspentManager) GetAmount(account uint32, asset hash.HashType) uint64 {
	log.Debugf(" account : %d ,,,,, asset : %x \n", account, asset)
	if account > uint32(len(um.utxos)-1) {
		return 0
	}
	collection := um.utxos[account]
	amount := uint64(0)

	if bytes.Equal(asset, genesis.GenesisAsset) {
		log.Debugf("default asset : %s \n", hex.EncodeToString(genesis.GenesisAsset))
		for iter := collection.txUtxos.Front(); iter != nil; iter = iter.Next() {
			utxoInfo := iter.Value.(*UnspentInfo)
			//if bytes.Equal(asset, utxoInfo.Body.(*structure.TxUtxo).Asset) {
			amount += utxoInfo.Body.Amount()
			//}
		}
		for iter := collection.exUtxos.Front(); iter != nil; iter = iter.Next() {
			amount += iter.Value.(*UnspentInfo).Body.Amount()
		}
		for iter := collection.cmUtxos.Front(); iter != nil; iter = iter.Next() {
			amount += iter.Value.(*UnspentInfo).Body.Amount()
		}
	} else {
		log.Debugf("other asset: %s \n", hex.EncodeToString(asset))
		for iter := collection.otherAssets[hash.HashTypeS(asset)].Front(); iter != nil; iter = iter.Next() {
			amount += iter.Value.(*UnspentInfo).Body.Amount()
		}
	}
	return amount
}

// ListUTXOsByAsset List all UTXOs  of designated assets and designated accounts
func (um *UnspentManager) ListUTXOsByAsset(account uint32, asset []byte) ([]*UnspentInfo, error) {

	collection := um.utxos[account]

	var assetUtxos []*UnspentInfo
	isBytes := bytes.Equal(asset, genesis.GenesisAsset)
	if isBytes {
		assetUtxos = make([]*UnspentInfo, 0, collection.txUtxos.Len()+collection.cmUtxos.Len()+collection.exUtxos.Len())
	} else {
		assetUtxos = make([]*UnspentInfo, 0, collection.otherAssets[hash.HashTypeS(asset)].Len())
	}

	if isBytes {
		for iter := collection.txUtxos.Front(); iter != nil; iter = iter.Next() {
			assetUtxos = append(assetUtxos, iter.Value.(*UnspentInfo))
		}
		for iter := collection.exUtxos.Front(); iter != nil; iter = iter.Next() {
			assetUtxos = append(assetUtxos, iter.Value.(*UnspentInfo))
		}
		for iter := collection.cmUtxos.Front(); iter != nil; iter = iter.Next() {
			assetUtxos = append(assetUtxos, iter.Value.(*UnspentInfo))
		}
	} else {
		for iter := collection.otherAssets[hash.HashTypeS(asset)].Front(); iter != nil; iter = iter.Next() {
			assetUtxos = append(assetUtxos, iter.Value.(*UnspentInfo))
		}
	}
	return assetUtxos, nil
}

// GetUTXOInfo get UTXO information
func (um *UnspentManager) GetUTXOInfo(account uint32, utxoID []byte) *UnspentInfo {
	ele := um.utxos[account].utxoIndex[string(utxoID)]
	if ele == nil {
		return nil
	}
	return ele.Value.(*UnspentInfo)
}

// HasUTXOInfo check whether UTXO already exists
func (um *UnspentManager) HasUTXOInfo(account uint32, utxoID []byte) bool {
	utxoEle := um.utxos[account].utxoIndex[string(utxoID)]
	return utxoEle != nil
}

// AddUTXOInfoStable add UTXOInfo to stable bucket
func (um *UnspentManager) AddUTXOInfoStable(tx database.Tx, info *UnspentInfo) error {
	collection := um.utxos[info.Account]
	key := info.Body.Key()
	keyString := string(key)
	if collection.utxoIndex[keyString] != nil {
		return nil
	}

	switch info.Body.Type() {
	case structure.TxUtxoType:
		asset := info.Body.(*structure.TxUtxo).Asset
		if bytes.Equal(asset, genesis.GenesisAsset) {
			collection.txUtxos.PushBack(info)
			collection.utxoIndex[keyString] = collection.txUtxos.Back()
		} else {
			assetList := collection.otherAssets[hash.HashTypeS(asset)]
			if assetList == nil {
				assetList = list.New()
				collection.otherAssets[hash.HashTypeS(asset)] = assetList
			}
			assetList.PushBack(info)
			collection.utxoIndex[keyString] = collection.otherAssets[hash.HashTypeS(asset)].Back()
		}
	case structure.CommissionUtxoType:
		collection.cmUtxos.PushBack(info)
		collection.utxoIndex[keyString] = collection.cmUtxos.Back()
	case structure.ExternalUtxoType:
		collection.exUtxos.PushBack(info)
		collection.utxoIndex[keyString] = collection.exUtxos.Back()
	}

	utxoKey := make([]byte, 5+len(key))
	binary.BigEndian.PutUint32(utxoKey[0:], info.Account)
	utxoKey[4] = info.Body.Type()
	copy(utxoKey[5:], key)

	utxoValue := info.Body.Value(0xFFFFFFFFFFFFFFFF)
	return walletdb.DbAddUtxo(tx, utxoKey, utxoValue)
}

// RemoveUTXOInfoUnstable  remove UTXOInfo from unstable bucket
func (um *UnspentManager) RemoveUTXOInfoUnstable(info *UnspentInfo) {
	collection := um.utxos[info.Account]
	utxoKey := string(info.Body.Key())
	utxoEle := collection.utxoIndex[utxoKey]
	if utxoEle == nil {
		return
	}
	delete(collection.utxoIndex, utxoKey)
	switch info.Body.Type() {
	case structure.TxUtxoType:
		asset := info.Body.(*structure.TxUtxo).Asset
		assetList := collection.otherAssets[hash.HashTypeS(asset)]
		if assetList == nil {
			collection.txUtxos.Remove(utxoEle)
		} else {
			assetList.Remove(utxoEle)
		}
	case structure.CommissionUtxoType:
		collection.cmUtxos.Remove(utxoEle)
	case structure.ExternalUtxoType:
		collection.exUtxos.Remove(utxoEle)
	}
}

// RemoveUTXOStable remove UTXOInfo from stable bucket
func (um *UnspentManager) RemoveUTXOStable(tx database.Tx, info *UnspentInfo) error {
	um.RemoveUTXOInfoUnstable(info)
	key := info.Body.Key()
	utxoKey := make([]byte, 5+len(key))
	binary.BigEndian.PutUint32(utxoKey[0:], info.Account)
	utxoKey[4] = info.Body.Type()
	copy(utxoKey[5:], key)
	return walletdb.DbRemoveUtxo(tx, utxoKey)
}

// AddNewAccount initialize a new collection for new account
func (um *UnspentManager) AddNewAccount(account uint32) {
	collection := new(UnspentCollection)
	collection.Init()
	um.utxos = append(um.utxos, collection)
}

// LoadAllUTXOsFromDb load all UTXOs from database
func (um *UnspentManager) LoadAllUTXOsFromDb() error {
	var utxoKeys, utxoValues [][]byte
	err := um.db.View(func(tx database.Tx) error {
		var err error
		utxoKeys, utxoValues, err = walletdb.DbFetchAllUtxos(tx)
		return err
	})
	if err != nil {
		return ErrLoadAllUTXO
	}

	utxoNum := len(utxoKeys)
	lastAccount, err := dbFetchLastAccount(um.db)
	if err != nil {
		log.Error("load last used account failed : ", err)
		return ErrLoadLastUsedAccount
	}
	accountNum := lastAccount + 1
	um.utxos = make([]*UnspentCollection, accountNum)
	for i := uint32(0); i < accountNum; i++ {
		um.utxos[i] = new(UnspentCollection)
		um.utxos[i].Init()
		assetList, err := dbFetchAssetListByAccount(um.db, i)
		if err != nil {
			log.Error(ErrLoadAssetList.Error())
			return ErrLoadAssetList
		}
		for _,asset := range assetList{
			if hash.Equal(asset, genesis.GenesisAsset) {
				continue
			}
			um.utxos[i].otherAssets[hash.HashTypeS(asset)] = list.New()
		}
	}

	for i := 0; i < utxoNum; i++ {
		account := binary.BigEndian.Uint32(utxoKeys[i][0:])
		utxoType := utxoKeys[i][4]
		utxoInfo := &UnspentInfo{
			Account: account,
		}
		switch utxoType {
		case structure.TxUtxoType:
			txUtxo := new(structure.TxUtxo)
			txUtxo.DeserializeFromKeyValue(utxoKeys[i][5:], utxoValues[i])
			utxoInfo.Body = txUtxo
			asset := txUtxo.Asset
			if bytes.Equal(asset, genesis.GenesisAsset) {
				um.utxos[account].txUtxos.PushBack(utxoInfo)
				um.utxos[account].utxoIndex[string(utxoKeys[i][5:])] = um.utxos[account].txUtxos.Back()
			} else {
				assetList := um.utxos[account].otherAssets[hash.HashTypeS(asset)]
				if assetList != nil {
					assetList.PushBack(utxoInfo)
					um.utxos[account].utxoIndex[string(utxoKeys[i][5:])] = assetList.Back()
				} else {
					assetList = list.New()
					um.utxos[account].otherAssets[hash.HashTypeS(asset)] = assetList
					assetList.PushBack(utxoInfo)
					um.utxos[account].utxoIndex[string(utxoKeys[i][5:])] = assetList.Back()
				}
			}
		case structure.CommissionUtxoType:
			cmUtxo := new(structure.CommissionUtxo)
			cmUtxo.DeserializeFromKeyValue(utxoKeys[i][5:], utxoValues[i])
			utxoInfo.Body = cmUtxo
			um.utxos[account].cmUtxos.PushBack(utxoInfo)
			um.utxos[account].utxoIndex[string(utxoKeys[i][5:])] = um.utxos[account].cmUtxos.Back()
		case structure.ExternalUtxoType:
			exUtxo := new(structure.ExternalUtxo)
			exUtxo.DeserializeFromKeyValue(utxoKeys[i][5:], utxoValues[i])
			utxoInfo.Body = exUtxo
			um.utxos[account].exUtxos.PushBack(utxoInfo)
			um.utxos[account].utxoIndex[string(utxoKeys[i][5:])] = um.utxos[account].exUtxos.Back()
		}
	}
	return nil
}

// SelectInputs Select eligible UTXO as input for trading based on UTXO selection strategy
func (um *UnspentManager) SelectInputs(crypto *addrmgr.CryptoKey, amount uint64, commission uint64, params PickerParam) (
	*SelectResult, error) {
	normalUtxos, commissionUtxos := um.divideSpendableUTXOs(params.Account, params.Asset)

	addrCollection := make(map[hash.HashTypeS]interface{})
	utxoNeeded := make([]*UnspentInfo, 0, len(normalUtxos)+len(commissionUtxos))
	groupNeeded := make([]*commissionGroup, 0, len(commissionUtxos))

	privkeyList := make([]asymmetric.PrivateKey, 0)
	addressList := make([]hash.HashType, 0)

	amountGot := uint64(0)
	commission ++
	for _, nUtxo := range normalUtxos {
		if params.ExcludedUTXO != nil && alreadySelectedUTXO(nUtxo, params) {
			log.Warn(" this utxo is already be selected")
			continue
		}
		amountGot += nUtxo.Body.Amount()
		//inputLength, inputType, addressExist + address, Unit, Message, Output
		if nUtxo.Body.Type() == structure.TxInputType {
			commission += 4 + 1 + 1 + 32 + 32 + 4 + 4
		} else {
			exSource := nUtxo.Body.(*structure.ExternalUtxo).ExternalSource
			commission += 4 + 1 + 32 + 1 + uint64(len(exSource))
		}

		address := hash.HashTypeS(nUtxo.Body.Address())

		if addrCollection[address] == nil &&!alreadySelectedAddress(nUtxo.Body.Address(), params){
			addrCollection[address] = 0
			privateKey, algType, err := um.FetchPrivateKey(hash.HashType(address), crypto)
			if err != nil {
				log.Errorf("can't get private key of address: %x \n", address)
				return nil, ErrFetchPrivateKeyByAddress
			}
			privkeyList = append(privkeyList, privateKey)
			addressList = append(addressList, hash.HashType(address))
			if algType == addrmgr.BLISS {
				commission += BlissAuthorBytes
			} else {
				commission += Secp256k1AuthorBytes
			}
		}
		utxoNeeded = append(utxoNeeded, nUtxo)
		if amountGot >= amount+commission {
			break
		}
	}
	if params.SelectCommission {
		for _, cUtxo := range commissionUtxos {
			if amountGot >= amount+commission {
				break
			}
			amountGot += cUtxo.allAmount
			commission += 4 + 1 + 32 + 8 + 8 //inputLen, inputType, address, from, to
			address := hash.HashTypeS(cUtxo.list[0].Body.Address())

			if addrCollection[address] == nil && !alreadySelectedAddress(hash.HashType(address), params){
				addrCollection[address] = 0
				commission += 4 + 32 + 4 + 72 + 4 + 65 + 1
				privkey, _, err := um.FetchPrivateKey(hash.HashType(address), crypto)
				if err != nil {
					log.Errorf("can't get private key of address: %x \n", address)
					return nil, ErrFetchPrivateKeyByAddress
				}
				privkeyList = append(privkeyList, privkey)
				addressList = append(addressList, hash.HashType(address))
			}
			groupNeeded = append(groupNeeded, cUtxo)
		}
	}

	if amountGot < amount+commission {
		log.Errorf("No enough bytes: want bytes %d , got bytes %d \n", amount+commission, amountGot)
		return nil, ErrNoEnoughFunds
	}
	sr := &SelectResult{
		Utxos:        utxoNeeded,
		CmGroups:     groupNeeded,
		PrivateKeys:  privkeyList,
		Addresses:    addressList,
		Commission:   commission,
		InputAmounts: amountGot,
	}
	return sr, nil
}

func (um *UnspentManager) divideSpendableUTXOs(account uint32, asset []byte) (normalUtxoList, commissionUtxoList) {

	collection := um.utxos[account]

	var normalUtxos normalUtxoList
	var commissionUtxos commissionUtxoList
	isBytes := bytes.Equal(asset, genesis.GenesisAsset)
	if isBytes {
		normalUtxos = make([]*UnspentInfo, 0, collection.txUtxos.Len()+collection.exUtxos.Len())
		commissionUtxos = make([]*commissionGroup, 0)
	} else {
		normalUtxos = make([]*UnspentInfo, 0, collection.otherAssets[hash.HashTypeS(asset)].Len())
	}

	if !isBytes {
		for iter := collection.otherAssets[hash.HashTypeS(asset)].Front(); iter != nil; iter = iter.Next() {
			if bytes.Equal(asset, iter.Value.(*UnspentInfo).Body.(*structure.TxUtxo).Asset) {
				normalUtxos = append(normalUtxos, iter.Value.(*UnspentInfo))
			}
		}
		sort.Sort(&normalUtxos)
		return normalUtxos, nil
	}
		for iter := collection.txUtxos.Front(); iter != nil; iter = iter.Next() {
			if bytes.Equal(asset, iter.Value.(*UnspentInfo).Body.(*structure.TxUtxo).Asset) {
				normalUtxos = append(normalUtxos, iter.Value.(*UnspentInfo))
			}
		}
		for iter := collection.exUtxos.Front(); iter != nil; iter = iter.Next() {
			normalUtxos = append(normalUtxos, iter.Value.(*UnspentInfo))

		}
		sort.Sort(&normalUtxos)

		mapping := make(map[hash.HashTypeS]int)
		i := 0
		for iter := collection.cmUtxos.Front(); iter != nil; iter = iter.Next() {
			utxo := iter.Value.(*UnspentInfo).Body.(*structure.CommissionUtxo)
			index, ok := mapping[hash.HashTypeS(utxo.Address())]
			if !ok {
				mapping[hash.HashTypeS(utxo.Address())] = i
				index = i
				i++
				group := &commissionGroup{
					list: make([]*UnspentInfo, 0, collection.cmUtxos.Len()),
				}
				commissionUtxos = append(commissionUtxos, group)
			}
			commissionUtxos[index].list = append(commissionUtxos[index].list, iter.Value.(*UnspentInfo))
			commissionUtxos[index].allAmount += utxo.Amount()
		}

		for _, group := range commissionUtxos {
			sort.Sort(group)
		}
		sort.Sort(&commissionUtxos)


	return normalUtxos, commissionUtxos
}

// FetchPrivateKey get the private key of the specified address
func (um *UnspentManager) FetchPrivateKey(address hash.HashType, crypto *addrmgr.CryptoKey) (asymmetric.PrivateKey, int, error) {
	var worker asymmetric.CipherSuite
	privKeyBytes, algType, err := FetchPrivKey(um.db, []byte(address), crypto)
	if err != nil {
		log.Debugf(" get address privateKey failed : %s \n", err.Error())
		return nil, -1, err
	}
	if algType == addrmgr.BLISS {
		worker = bliss.NewCipherSuite()
	} else {
		worker = secp256k1.NewCipherSuite()
	}
	privKey, err := worker.UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return nil, -1, ErrUnmarshalPrivateKey
	}
	return privKey, algType, nil
}

func alreadySelectedUTXO(utxo *UnspentInfo, picker PickerParam) bool {
	for _, existUtxo := range picker.ExcludedUTXO {
		if existUtxo == utxo {
			return true
		}
	}
	return false
}

func alreadySelectedAddress(addr hash.HashType, picker PickerParam) bool {
	for _, existUtxo := range picker.ExcludedUTXO {
		if bytes.Equal(existUtxo.Body.Address(), addr) {
			return true
		}
	}

	for _, existAddr := range picker.ExcludedAddress {
		if bytes.Equal(addr, existAddr) {
			return true
		}
	}

	return false
}

func dbFetchLastAccount(db database.DB) (uint32, error) {
	var accountIndex uint32

	err := db.View(func(tx database.Tx) error {
		var err error
		accountIndex, err = walletdb.DbFetchLastAccount(tx)
		return err
	})
	return accountIndex, err
}

// FetchPrivKey fetch private key from database
func FetchPrivKey(db database.DB, address []byte, crypto *addrmgr.CryptoKey) ([]byte, int, error) {
	var privKeyBytes []byte
	var acctType int
	err := db.View(func(tx database.Tx) error {

		addrBytes, err := walletdb.DbFetchAddress(tx, hash.HashType(address))
		if err != nil {
			log.Errorf(" can't find input address : ", err)
			return err
		}
		addr, err := addrmgr.DecodeAddress(addrBytes)
		if err != nil {
			return err
		}

		acctInfoBytes, err := walletdb.DbFetchAccountInfo(tx, addr.Account)
		if err != nil {
			return err
		}
		acctInfo := new(addrmgr.AccountInfo)
		err = acctInfo.DecodeAccountInfo(acctInfoBytes)
		if err != nil {
			return err
		}
		acctType = acctInfo.AccountType
		if acctInfo.AccountType == addrmgr.BLISS {
			privExtendedKey, err := dbFetchPrivateKey(db, addr.PubKey)
			if err != nil {
				return err
			}
			privKeyBytes = privExtendedKey.Key
		} else {
			acctPrivKeyBytes, err := crypto.Decrypt(acctInfo.PrivKeyEnc)
			if err != nil {
				return ErrDecryptPrivateKey
			}
			acctPrivKey := new(addrmgr.ExtendedKey)
			err = acctPrivKey.UnMarshal(acctPrivKeyBytes)
			if err != nil {
				return ErrUnmarshalPrivateKey
			}
			branch := uint32(0)
			if addr.Internal {
				branch = 1
			}
			privExtendedKey, err := acctPrivKey.DerivPrivKey(branch,
				addr.Index, addrmgr.SECP256K1)
			if err != nil {
				return err
			}
			privKeyBytes = privExtendedKey.Key
		}
		return nil
	})
	if err != nil {
		return nil, 0, ErrFetchPrivateKeyByAddress
	}
	return privKeyBytes, acctType, nil
}

func dbFetchPrivateKey(db database.DB, pubkey []byte) (*addrmgr.ExtendedKey,
	error) {

	var privBytes []byte
	err := db.View(func(tx database.Tx) error {
		var err error
		privBytes, err = walletdb.DbFetchPrivateKey(tx, pubkey)
		return err
	})
	if err != nil {
		return nil, err
	}
	var privKey addrmgr.ExtendedKey
	err = privKey.UnMarshal(privBytes)
	if err != nil {
		return nil, err
	}

	return &privKey, nil
}

func dbFetchAssetListByAccount(db database.DB,
	account uint32) ([]hash.HashType, error){

	var accountBytes []byte
	err := db.View(func(tx database.Tx) error {
		var err error
		accountBytes, err = walletdb.DbFetchAccountInfo(tx, account)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	acctInfo := new(addrmgr.AccountInfo)
	err = acctInfo.DecodeAccountInfo(accountBytes)
	if err != nil {
		return nil, err
	}

	return acctInfo.AssetList, nil
}
