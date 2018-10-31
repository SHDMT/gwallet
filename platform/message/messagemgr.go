package message

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"github.com/SHDMT/crypto/asymmetric"
	"github.com/SHDMT/crypto/bliss"
	"github.com/SHDMT/crypto/secp256k1"
	"github.com/pkg/errors"
	"fmt"
	"github.com/SHDMT/gravity/infrastructure/crypto/hash"
	"github.com/SHDMT/gravity/platform/consensus/genesis"
	"github.com/SHDMT/gravity/platform/consensus/structure"
	"github.com/SHDMT/gwallet/infrastructure/database"
	"github.com/SHDMT/gwallet/infrastructure/log"
	"github.com/SHDMT/gwallet/platform/addrmgr"
	"github.com/SHDMT/gwallet/platform/grpc/walletrpc"
	"github.com/SHDMT/gwallet/platform/utxo"
	"github.com/SHDMT/gwallet/platform/walletdb"
	"strings"
	"time"
)

var (
	errNoEnoughFunds = " you have no enough funds"
	errUpdateAccountFailed = " update account lastUsed address failed"
	errAlreadyReceivedUTXO = " already received UTXO, It may be caused by a double-spend"
	errUnrecognizedAccount = " unrecognized output account"
	errUnmarshalFailed = "failed to Unmarshal"
)

// PaymentARGS all the information needed to support PaymentARGS
type PaymentARGS struct {
	AccountName string
	SendPairs   map[string]uint64
}

// TextARGS all the information needed to support TextARGS
type TextARGS struct {
	AccountName string
	Text        string
}

// InvokeARGS all the information needed to support InvokeARGS
type InvokeARGS struct {
	AccountName     string
	Asset           []byte
	ContractAddress []byte
	AmountList      []uint64
	Params          []byte
}

// IssueARGS all the information needed to support IssueARGS
type IssueARGS struct {
	AccountName        string
	AssetName          string
	Cap                int64
	FixedDenominations bool
	Denominations      []uint32
	Contracts          []*structure.ContractDef
	AllocationAddr     [][]byte
	AllocationAmount   []int64
	PublisherAddress   hash.HashType
	Note               []byte
}

// DeployARGS all the information needed to support DeployARGS
type DeployARGS struct {
	AccountName string
	Contracts   [][]byte
}

// IssueWithJsonArgs all the information needed to support IssueWithJsonArgs
type IssueWithJsonArgs struct {
	PaymentAccount string
	IssueJson	   []byte
	Send 		   bool
}

// DeployWithJsonArgs all the information needed to support DeployWithJsonArgs
type DeployWithJsonArgs struct {
	PaymentAccount string
	DeployJson	   []byte
	Send 		   bool
}

// InvokeWithJsonArgs all the information needed to support InvokeWithJsonArgs
type InvokeWithJsonArgs struct {
	PaymentAccount string
	InvokeJson	   []byte
	InvokeAmount   uint64
	Send 		   bool
}

// MsgKey message key
type MsgKey struct {
	unitHash []byte
	id       uint32
}

// Balance default account gravity asset
type Balance struct {
	TotalAmount   uint64 `json:"total"`
	PendingAmount uint64 `json:"pending"`
}

// WalletAsset all the information needed to support asset
type WalletAsset struct {
	Name         string        `json:"name"`
	AssetID      hash.HashType `json:"id"`
	AssetBalance *Balance      `json:"balance"`
}

// WalletAccount all the information needed to support account
type WalletAccount struct {
	Name         string         `json:"name"`
	AccountIndex uint32         `json:"index"`
	Assets       []*WalletAsset `json:"assets"`
}

// TXManager all the information needed to support TXManager
type TXManager struct {
	db      database.DB
	utxoMgr *utxo.UnspentManager
	addrMgr *addrmgr.AddressManager

	unstableMessages map[hash.HashTypeS][]*messageInfo
	amount           uint64
	pendingAmount    uint64

	accounts []*WalletAccount
}

// NewTXManager create a new TXManager
func NewTXManager(db database.DB, utxoMgr *utxo.UnspentManager, addrMgr *addrmgr.AddressManager) (*TXManager, error) {

	txMgr := &TXManager{
		db:               db,
		utxoMgr:          utxoMgr,
		addrMgr:          addrMgr,
		unstableMessages: make(map[hash.HashTypeS][]*messageInfo),
	}
	_, _, err := txMgr.LoadAccounts()
	if err != nil {
		log.Errorf(" can't load account from db: ", err)
		return nil, errors.New(" load accounts from db err")
	}

	return txMgr, nil
}

// LoadAccounts load all accounts from database
func (tm *TXManager) LoadAccounts() (uint64, []*WalletAccount, error) {
	var totalAmount uint64
	accounts, err := dbFetchAccountInfo(tm.db)
	if err != nil || len(accounts) == 0 {
		log.Error(" load account failed : ", err)
		return 0, nil, err
	}

	walletAcct := make([]*WalletAccount, 0)
	for _, acct := range accounts {
		acctAssets := make([]*WalletAsset, 0)
		for _, asset := range acct.AssetList {

			amount := tm.utxoMgr.GetAmount(acct.AccountIndex, asset)
			balance := &Balance{
				TotalAmount:   amount,
				PendingAmount: uint64(0),
			}
			if bytes.Equal(asset, genesis.GenesisAsset) {
				totalAmount += amount
			}

			assetName, err := dbFetchAssetName(tm.db, asset)
			if err != nil {
				log.Warn(" fetch asset name failed : ", err)
				continue
			}
			wAsset := &WalletAsset{
				Name:         assetName,
				AssetID:      asset,
				AssetBalance: balance,
			}
			acctAssets = append(acctAssets, wAsset)
		}

		wacct := &WalletAccount{
			Name:         acct.AccountName,
			AccountIndex: acct.AccountIndex,
			Assets:       acctAssets,
		}
		walletAcct = append(walletAcct, wacct)
	}

	tm.accounts = walletAcct
	tm.amount = totalAmount

	return totalAmount, walletAcct, nil
}

// CreatePaymentMessage create payment message
func (tm *TXManager) CreatePaymentMessage(cryptoKey *addrmgr.CryptoKey, pairs map[string]uint64, commission uint64, param utxo.PickerParam) (
	*structure.PaymentMessage, *utxo.SelectResult, *addrmgr.Address, error) {
	pm := new(structure.PaymentMessage)
	pm.Header = new(structure.MessageHeader)
	pm.Header.Version = structure.Version
	pm.Header.App = structure.PaymentMessageType
	pm.Asset = param.Asset
	commission += 4 + 1 + 1 + 4 + 32 + 32
	var amount uint64
	for _, am := range pairs {
		amount += am
	}

	outputNum := len(pairs) + 1
	if amount == 0 {
		outputNum = 1
	}

	pm.Outputs = make([]*structure.Output, outputNum)

	if amount != 0 {
		i := 0
		for address, amt := range pairs {
			if amt == 0 {
				continue
			}

			//toAddress, _, err := base58.CheckDecode(address)
			toAddress, err := base64.StdEncoding.DecodeString(address)
			if err != nil {
				fmt.Println(" to address error : ", err)
				return nil, nil, nil, errors.New(" can't parse toAddress ")
			}
			destOutput := &structure.Output{
				Amount:  amt,
				Address: toAddress,
				Extends: nil,
			}
			pm.Outputs[i] = destOutput
			i++
		}
	}

	changeOutput := &structure.Output{
		Amount:  0,
		Address: make([]byte, 32),
		Extends: nil,
	}
	pm.Outputs[outputNum-1] = changeOutput
	commission += 1 + (4+8+32+1)*uint64(outputNum)

	sr, err := tm.utxoMgr.SelectInputs(cryptoKey, amount, commission, param)
	if err != nil {
		log.Errorf("Failed to select inputs: %s\n", err)
		return nil, nil, nil, fmt.Errorf(errNoEnoughFunds)
	}
	pm.Inputs = make([]structure.Input, len(sr.Utxos)+len(sr.CmGroups))
	i := 0
	for _, utxoInfo := range sr.Utxos {
		switch utxoInfo.Body.(type) {
		case *structure.TxUtxo:
			txInput := &structure.TxInput{
				Address:       utxoInfo.Body.Address(),
				SourceUnit:    utxoInfo.Body.(*structure.TxUtxo).Unit,
				SourceMessage: utxoInfo.Body.(*structure.TxUtxo).Message,
				SourceOutput:  utxoInfo.Body.(*structure.TxUtxo).Output,
			}
			pm.Inputs[i] = txInput
			i++
		case *structure.ExternalUtxo:
			exInput := &structure.ExternalInput{
				Address:        utxoInfo.Body.(*structure.ExternalUtxo).Address(),
				ExternalSource: utxoInfo.Body.(*structure.ExternalUtxo).ExternalSource,
			}
			pm.Inputs[i] = exInput
			i++
		default:
		}
	}

	for _, cmGroup := range sr.CmGroups {
		cmInput := &structure.CommissionInput{
			Address:   cmGroup.Address(),
			FromIndex: cmGroup.FromMci(),
			ToIndex:   cmGroup.ToMci(),
		}
		pm.Inputs[i] = cmInput
		i++
	}

	address, err := tm.addrMgr.CreateNewAddress(param.Account, true)
	if err != nil {
		log.Error("can't derive change address")
		return nil, nil, nil, fmt.Errorf("can't derive change address: %s ", err)
	}
	changeOutput.Address = hash.HashType(address.Address)
	changeOutput.Amount = sr.InputAmounts - sr.Commission - amount
	pm.Header.PayloadHash = pm.CalcPayloadHash()
	return pm, sr, address, nil
}

// CreateTextMessage create a text message
func (tm *TXManager) CreateTextMessage(text string) (*structure.TextMessage, error) {
	t := new(structure.TextMessage)
	t.Header = new(structure.MessageHeader)
	t.Header.Version = structure.Version
	t.Header.App = structure.TextMessageType
	t.Content = []byte(text)
	t.Header.PayloadHash = t.CalcPayloadHash()
	return t, nil
}

// CreateInvokeMessage execute the specified smart contract
func (tm *TXManager) CreateInvokeMessage(arg *InvokeARGS, cryptoKey *addrmgr.CryptoKey, commission uint64, param utxo.PickerParam) (*structure.InvokeMessage, *utxo.SelectResult, *addrmgr.Address, error) {
	contract := arg.ContractAddress
	contractParam := arg.Params
	invokeMessage := new(structure.InvokeMessage)
	invokeMessage.Header = new(structure.MessageHeader)
	invokeMessage.Header.Version = structure.Version
	invokeMessage.Header.App = structure.InvokeMessageType

	invokeMessage.Asset = param.Asset
	invokeMessage.ContractAddr = contract

	err := invokeMessage.ParseParamsFromJSON(contractParam)
	if err != nil {
		log.Error(" can't parse json param")
		return  nil, nil, nil, fmt.Errorf(" can't parse json param")
	}

	var totalAmount = uint64(0)
	for _, output := range invokeMessage.Outputs {
		totalAmount += output.Amount
	}

	sr, err := tm.utxoMgr.SelectInputs(cryptoKey, totalAmount, commission, param)
	if err != nil {
		log.Errorf("Failed to select inputs: %s\n", err)
		return nil, nil, nil, fmt.Errorf(" No enough funds \n")
	}
	inputs := make([]*structure.ContractInput, 0)
	for _, utxoInfo := range sr.Utxos {
		switch utxo := utxoInfo.Body.(type) {
		case *structure.TxUtxo:
			txInput := structure.NewContractInput()
			txInput.SourceUnit = utxo.Unit
			txInput.SourceMessage = utxo.Message
			txInput.SourceOutput = utxo.Output
			txInput.AddParam("addr", utxoInfo.Body.Address())
			log.Debug(" add contract input to invoke message")
			inputs = append(inputs, txInput)
		default:
			log.Debug(" unsupported utxo type")
		}
	}
	invokeMessage.Inputs = inputs

	var changeAddress *addrmgr.Address
	if (sr.InputAmounts - totalAmount) != 0 {
		changeAddress, err = tm.addrMgr.CreateNewAddress(param.Account, true)
		if err != nil {
			log.Error("can't derive change address")
			return  nil, nil, nil, fmt.Errorf("can't derive change address: %s ", err)
		}
		change := structure.NewContractOutput()
		change.Amount = sr.InputAmounts - totalAmount
		change.AddParam("addr", hash.HashType(changeAddress.Address))
		invokeMessage.Outputs = append(invokeMessage.Outputs, change)
	}

	invokeMessage.Header.PayloadHash = invokeMessage.CalcPayloadHash()
	return  invokeMessage, sr, changeAddress, nil
}

// CreateIssueMessage issue a new asset
func (tm *TXManager) CreateIssueMessage(arg *IssueARGS) (*structure.IssueMessage, error) {
	name := arg.AssetName
	assetCap := arg.Cap
	fixedDenominations := arg.FixedDenominations
	denominations := arg.Denominations
	contracts := arg.Contracts
	allocationAddr := make([]hash.HashType, len(arg.AllocationAddr))
	for i, addrBytes := range arg.AllocationAddr {
		addr := hash.HashType(addrBytes)
		allocationAddr[i] = addr
	}
	allocationAmount :=  arg.AllocationAmount
	publisherAddress :=  arg.PublisherAddress
	note := arg.Note

	issueMessage := new(structure.IssueMessage)
	issueMessage.Header = new(structure.MessageHeader)
	issueMessage.Header.Version = structure.Version
	issueMessage.Header.App = structure.IssueMessageType

	issueMessage.Name = name
	issueMessage.Cap = assetCap
	issueMessage.FixedDenominations = fixedDenominations
	issueMessage.Denominations = denominations
	issueMessage.Contracts = contracts
	issueMessage.AllocationAddr = allocationAddr
	issueMessage.AllocationAmount = allocationAmount
	issueMessage.PublisherAddress = publisherAddress
	issueMessage.Note = note

	issueMessage.Header.PayloadHash = issueMessage.CalcPayloadHash()

	return issueMessage, nil
}

// CreateDeployMessage deploy new smart contracts
func (tm *TXManager) CreateDeployMessage(contracts [][]byte) (*structure.DeployMessage, error) {

	deployMessage := new(structure.DeployMessage)
	deployMessage.Header = new(structure.MessageHeader)
	deployMessage.Header.Version = structure.Version
	deployMessage.Header.App = structure.DeployMessageType

	newContracts := make([]*structure.Contract, 0, len(contracts))
	for _, contractBytes := range contracts {
		contract := new(structure.Contract)
		contract.Deserialize(contractBytes)
		contract.CalcAddress()
		newContracts = append(newContracts, contract)
	}

	deployMessage.Contracts = newContracts

	deployMessage.Header.PayloadHash = deployMessage.CalcPayloadHash()

	return deployMessage, nil
}

// CreateInvokeMessageWithJson
func (m *TXManager) CreateInvokeMessageWithJson(acct uint32,amount uint64,invokeJson []byte, cryptoKey *addrmgr.CryptoKey)(*structure.InvokeMessage, *utxo.SelectResult, *addrmgr.Address, error){
	invokeMessage, err := unMarshalInvokeMessage(invokeJson)
	if err != nil {
		return nil, nil, nil, err
	}
	log.Debugf("invokeMessageWithJson : %+v \n", invokeMessage)

	var changeAddress *addrmgr.Address
	var sr *utxo.SelectResult
	if len(invokeMessage.Inputs) > 0 && amount == 0{
		// 初始化一个selectResult 对象
		sr = &utxo.SelectResult{
			Utxos:  make([]*utxo.UnspentInfo,0),
			PrivateKeys:make([]asymmetric.PrivateKey,0),
			Addresses:make([]hash.HashType,0),
			InputAmounts: uint64(0),
			Commission: uint64(0),
		}
		//1. 遍历所有的inputs,从数据库中找出对应的UTXO
		for _,input := range invokeMessage.Inputs{
			// 1. 组装钱包需要的utxoKey
			key := input.KeySerialize()
			utxoKey := make([]byte, 5+len(key))
			binary.BigEndian.PutUint32(utxoKey[0:], acct)
			utxoKey[4] = 0
			copy(utxoKey[5:], key)
			// 2. 取出每个UTXO
			txUTXO, err:= dbFetchUTXO(m.db, utxoKey)
			if err != nil {
				return nil, nil, nil, fmt.Errorf(" can't find specified input")
			}
			uTXOInfo := &utxo.UnspentInfo{
				Account: acct,
				Body:txUTXO,
			}
			if isDoubleSpent(sr, uTXOInfo) {
				return nil, nil,nil, fmt.Errorf(" double spent .")
			}
			sr.Utxos = append(sr.Utxos, uTXOInfo)
			sr.Commission += 4 + 1 + 1 + 32 + 32 + 4 + 4
			address := txUTXO.Address()
			if !isAlreadySelectedAddress(sr, address) {
				sr.Addresses = append(sr.Addresses, address)
				selectedPrivateKey, algType , err := m.utxoMgr.FetchPrivateKey(address, cryptoKey)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("can't find address's privateKey from database")
				}
				if algType == addrmgr.BLISS{
					sr.Commission += utxo.BlissAuthorBytes
				}else if algType == addrmgr.SECP256K1 {
					sr.Commission += utxo.Secp256k1AuthorBytes
				}else {
					return nil, nil, nil, fmt.Errorf("unsupported algorithm")
				}
				sr.PrivateKeys = append(sr.PrivateKeys, selectedPrivateKey)
			}
		}
		//3. 根据inputs 计算找零金额， 并生成找零output
		if (sr.InputAmounts - amount) < 0 {
			return  nil, nil, nil, fmt.Errorf(" not enough funds ")
		}
	} else if len(invokeMessage.Inputs) == 0 && amount > 0 {
		inputs := make([]*structure.ContractInput, 0)
		param := utxo.PickerParam{
			Account:          acct,
			Asset:            invokeMessage.Asset,
			SelectCommission: false,
		}

		sr, err = m.utxoMgr.SelectInputs(cryptoKey, amount, 0, param)
		if err != nil {
			log.Errorf("Failed to select inputs: %s\n", err)
			return nil, nil, nil, fmt.Errorf(" No enough funds \n")
		}
		log.Debugf(" --- invoke message utxo Num is : %d \n", len(sr.Utxos))

		for _, utxoInfo := range sr.Utxos {
			switch utxo := utxoInfo.Body.(type) {
			case *structure.TxUtxo:
				txInput := structure.NewContractInput()
				txInput.SourceUnit = utxo.Unit
				txInput.SourceMessage = utxo.Message
				txInput.SourceOutput = utxo.Output
				txInput.AddParam("addr", utxoInfo.Body.Address())
				log.Debug(" add contract input to invoke message")
				inputs = append(inputs, txInput)
			default:
				log.Debug(" unsupported utxo type")
			}
		}
		invokeMessage.Inputs = inputs
	}else {
		return nil,nil,nil, fmt.Errorf("不能同时指定转账金额 和 使用的UTXO")
	}
	// 判断是否需要找零
	if (sr.InputAmounts - amount) > 0 {
		changeAddress, err = m.addrMgr.CreateNewAddress(acct, true)
		if err != nil {
			log.Error("can't derive change address")
			return nil, nil, nil, fmt.Errorf("can't derive change address: %s ", err)
		}
		log.Debugf(" unit commission is : %d \n", sr.Commission)

		change := structure.NewContractOutput()
		change.Amount = sr.InputAmounts - amount
		change.AddParam("addr", hash.HashType(changeAddress.Address))
		invokeMessage.Outputs = append(invokeMessage.Outputs, change)
	}
	log.Debug(" invoke message inputs num is : ", len(invokeMessage.Inputs))

	invokeMessage.Header.PayloadHash = invokeMessage.CalcPayloadHash()
	return invokeMessage, sr, changeAddress, nil
}

// CreateIssueMessageWithJson
func (m *TXManager) CreateIssueMessageWithJson(issueJson []byte,commission uint64, cryptoKey *addrmgr.CryptoKey)(*structure.IssueMessage, asymmetric.PrivateKey,uint64, error){
	log.Debugf("issueJson : %s \n", string(issueJson))
	log.Debugf("issueJson: %x \n", issueJson)
	issueMessage, err := unMarshalIssueMessage(issueJson)
	if err != nil {
		return nil, nil, 0, err
	}
	log.Debugf("issueMessage : %+v \n", issueMessage)
	var publisherPrivKey asymmetric.PrivateKey
	if issueMessage.PublisherAddress == nil {
		addr, err := m.addrMgr.NewAddress("default", true)
		if err != nil {
			log.Errorf(" set publisher address failed ,can't get a new address ")
			return nil,nil, 0,fmt.Errorf(" set publisher address failed ,can't get a new address : %s ", err)
		}
		privKeyBytes, _, err := utxo.FetchPrivKey(m.db, addr.Address, cryptoKey)
		if err != nil {
			log.Errorf("get privateKey of address : %s  failed ", base64.StdEncoding.EncodeToString(addr.Address))
			return nil, nil, 0,fmt.Errorf("get privateKey of address : %s  failed ", base64.StdEncoding.EncodeToString(addr.Address))
		}
		worker := secp256k1.NewCipherSuite()
		publisherPrivKey, err = worker.UnmarshalPrivateKey(privKeyBytes)
		if err != nil {
			return nil, nil,0, fmt.Errorf(" can't unmarshal publisher address private key")
		}
		commission += utxo.Secp256k1AuthorBytes
		issueMessage.PublisherAddress = addr.Address
	} else {
		privKeyBytes, algType, err := utxo.FetchPrivKey(m.db, issueMessage.PublisherAddress, cryptoKey)
		if err != nil {
			log.Errorf("get privateKey of address : %s  failed ", base64.StdEncoding.EncodeToString(issueMessage.PublisherAddress))
			return nil, nil, 0, fmt.Errorf("get privateKey of address : %s  failed ", base64.StdEncoding.EncodeToString(issueMessage.PublisherAddress))
		}
		var worker asymmetric.CipherSuite
		if algType == addrmgr.BLISS {
			worker = bliss.NewCipherSuite()
			commission += utxo.BlissAuthorBytes
		} else if algType == addrmgr.SECP256K1 {
			worker = secp256k1.NewCipherSuite()
			commission += utxo.Secp256k1AuthorBytes
		} else {
			panic("unsupported algorithm")
		}
		publisherPrivKey, err = worker.UnmarshalPrivateKey(privKeyBytes)
		if err != nil {
			return nil, nil, 0, fmt.Errorf(" can't unmarshal publisher address private key")
		}
	}

	issueMessage.Header.PayloadHash = issueMessage.CalcPayloadHash()
	return issueMessage,publisherPrivKey,commission, nil
}

// CreateDeployMessageWithJson
func (tm *TXManager) CreateDeployMessageWithJson(deployJson []byte) (*structure.DeployMessage, error) {
	deployMessage, err := unMarshalDeployMessage(deployJson)
	if err != nil {
		return nil, err
	}
	log.Debugf(" deployContractWithJson : %+v \n", deployMessage)
	deployMessage.Header.PayloadHash = deployMessage.CalcPayloadHash()
	return deployMessage, nil
}

// ReceiveMessage 处理 gravity 收到的与钱包相关的message
func (tm *TXManager) ReceiveMessage(message structure.Message, unitHash hash.HashType, messageID uint32, callback func([]byte) (string, error)) {
	log.Debugf("----- : Receive message  : %T, unitHash : %x, messageId : %x  \n", message, unitHash, messageID)
	messageInfos := tm.unstableMessages[hash.HashTypeS(unitHash)]
	for _, mInfo := range messageInfos {
		if mInfo.messageID == messageID {
			log.Warnf("Unit %v already received\n", unitHash)
			return
		}
	}

	utxosToAdd := make([]*utxo.UnspentInfo, 0)
	utxosToRemove := make([]*utxo.UnspentInfo, 0)
	switch message.(type) {
	case *structure.PaymentMessage:
		pm := message.(*structure.PaymentMessage)

		for _, input := range pm.Inputs {
			isMyAddress := false
			acct := addrmgr.DefaultAccountNum
			var err error
			tm.db.View(func(tx database.Tx) error {
				acct, isMyAddress, err = dbIsMyAddress(tx, input.GetAddress())
				if err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				if isMyAddress {
					log.Warn(" Unrecognized input account. ")
				}
				continue
			}
			if !isMyAddress {
				continue
			}
			err = updateAccountLastUsed(tm.db, input.GetAddress())
			if err != nil {
				log.Warn(errUpdateAccountFailed)
			}
			switch input.(type) {
			case *structure.TxInput:
				utxoKey := input.(*structure.TxInput).KeySerialize()
				utxoInfo := tm.utxoMgr.GetUTXOInfo(acct, utxoKey)
				if utxoInfo == nil {
					log.Warnf(errAlreadyReceivedUTXO)
				} else {
					tm.utxoMgr.RemoveUTXOInfoUnstable(utxoInfo)
					utxosToRemove = append(utxosToRemove, utxoInfo)
					for _, account := range tm.accounts {
						if account.AccountIndex == acct {
							for _, asset := range account.Assets {
								if hash.Equal(asset.AssetID, pm.Asset) {
									asset.AssetBalance.TotalAmount -= utxoInfo.Body.Amount()
									if bytes.Equal(pm.Asset, genesis.GenesisAsset) {
										tm.amount -= utxoInfo.Body.Amount()
									}
								}
							}
						}
					}
				}

			case *structure.ExternalInput:
				utxoKey := input.(*structure.ExternalInput).KeySerialize()
				utxoInfo := tm.utxoMgr.GetUTXOInfo(acct, utxoKey)
				if utxoInfo == nil {
					log.Warnf(errAlreadyReceivedUTXO)
				} else {
					tm.utxoMgr.RemoveUTXOInfoUnstable(utxoInfo)
					utxosToRemove = append(utxosToRemove, utxoInfo)
					for _, account := range tm.accounts {
						if account.AccountIndex == acct {
							for _, asset := range account.Assets {
								if hash.Equal(asset.AssetID, genesis.GenesisAsset) {
									asset.AssetBalance.TotalAmount -= utxoInfo.Body.Amount()
									tm.amount -= utxoInfo.Body.Amount()
								}
							}
						}
					}
				}

			case *structure.CommissionInput:
				ci := input.(*structure.CommissionInput)
				valid := false
				for mci := ci.FromIndex; mci <= ci.ToIndex; mci++ {
					utxoKey := ci.KeySerialize(mci)
					utxoInfo := tm.utxoMgr.GetUTXOInfo(acct, utxoKey)
					if utxoInfo != nil {
						valid = true
						tm.utxoMgr.RemoveUTXOInfoUnstable(utxoInfo)
						utxosToRemove = append(utxosToRemove, utxoInfo)
						for _, account := range tm.accounts {
							if account.AccountIndex == acct {
								for _, asset := range account.Assets {
									if hash.Equal(asset.AssetID, genesis.GenesisAsset) {
										asset.AssetBalance.TotalAmount -= utxoInfo.Body.Amount()
										tm.amount -= utxoInfo.Body.Amount()
									}
								}
							}
						}
					}
				}
				if !valid {
					log.Warnf(errAlreadyReceivedUTXO)
				}
			}
		}

		for i, output := range pm.Outputs {
			isMyAddress := false
			acct := addrmgr.DefaultAccountNum
			var err error
			tm.db.View(func(tx database.Tx) error {
				acct, isMyAddress, err = dbIsMyAddress(tx, output.Address)
				return err
			})
			if err != nil {
				if isMyAddress {
					log.Warn(errUnrecognizedAccount)
				}
				continue
			}
			if !isMyAddress {
				continue
			}
			err = updateAccountLastUsed(tm.db, output.Address)
			if err != nil {
				log.Warn(errUpdateAccountFailed)
			}
			txUtxo := output.ToUtxo(pm.Asset, unitHash, messageID, uint32(i))
			utxoInfo := &utxo.UnspentInfo{
				Account: acct,
				Body:    txUtxo,
			}

			if !tm.utxoMgr.HasUTXOInfo(acct, txUtxo.Key()) {
				for _, account := range tm.accounts {
					if account.AccountIndex == acct {
						hasAsset := false
						for _, asset := range account.Assets {
							log.Debugf(" account asset : %x \n", asset.AssetID)
							log.Debugf(" received asset: %x \n", pm.Asset)
							if hash.Equal(asset.AssetID, pm.Asset) {
								hasAsset = true
								asset.AssetBalance.TotalAmount += output.Amount
								asset.AssetBalance.PendingAmount += output.Amount
								if bytes.Equal(pm.Asset, genesis.GenesisAsset) {
									tm.amount += output.Amount
									tm.pendingAmount += output.Amount
								}
							}
						}
						if !hasAsset {
							// issueMessage 发行的只能是一种新资产
							newBalance := &Balance{
								TotalAmount: utxoInfo.Body.Amount(),
								PendingAmount: utxoInfo.Body.Amount(),
							}
							unithashStr := fmt.Sprintf("%x", pm.Asset)
							assetName :=  string([]byte(unithashStr)[:6])
							if callback != nil{
								assetName,err = callback(pm.Asset)
								if err != nil {
									log.Warn("Can't get assetName from gravity.")
								}
							}
							addNewAssetForAccount(tm.db, acct,assetName, pm.Asset)
							newAsset := &WalletAsset{
								Name: assetName,
								AssetID: pm.Asset,
								AssetBalance:newBalance,
							}
							account.Assets = append(account.Assets, newAsset)
						}
					}
				}
				utxosToAdd = append(utxosToAdd, utxoInfo)
			} else {
				log.Warnf("uTXO of unit %v, message %v, output %v is already received\n", unitHash, messageID, i)
			}
		}
	case *structure.IssueMessage:
		im := message.(*structure.IssueMessage)

		utxos := im.GenerateUtxos(unitHash, messageID)
		for i, eachUtxo := range utxos {
			isMyAddress := false
			acct := addrmgr.DefaultAccountNum
			var err error
			tm.db.View(func(tx database.Tx) error {
				acct, isMyAddress, err = dbIsMyAddress(tx, eachUtxo.Address())
				return err
			})
			if err != nil {
				if isMyAddress {
					log.Warn(errUnrecognizedAccount)
				}
				continue
			}
			if !isMyAddress {
				continue
			}

			err = updateAccountLastUsed(tm.db, eachUtxo.Address())
			if err != nil {
				log.Warn(" update lastused address failed .")
			}
			utxoInfo := &utxo.UnspentInfo{
				Account: acct,
				Body:    eachUtxo,
			}

			if !tm.utxoMgr.HasUTXOInfo(acct, eachUtxo.Key()) {
				for _, account := range tm.accounts {
					if account.AccountIndex == acct {
						hasAsset := false
						for _,asset := range account.Assets {
							if hash.Equal(asset.AssetID,unitHash) {
								hasAsset = true
								asset.AssetBalance.TotalAmount += utxoInfo.Body.Amount()
								asset.AssetBalance.PendingAmount += utxoInfo.Body.Amount()
								if bytes.Equal(unitHash,genesis.GenesisAsset) {
									tm.amount += utxoInfo.Body.Amount()
									tm.pendingAmount += utxoInfo.Body.Amount()
								}
							}
						}
						if !hasAsset {
							newBalance := &Balance{
								TotalAmount:   eachUtxo.Amount(),
								PendingAmount: eachUtxo.Amount(),
							}
							newAsset := &WalletAsset{
								Name:         im.Name,
								AssetID:      unitHash,
								AssetBalance: newBalance,
							}
							account.Assets = append(account.Assets, newAsset)
							if bytes.Equal(unitHash, genesis.GenesisAsset) {
								tm.amount += utxoInfo.Body.Amount()
								tm.pendingAmount += utxoInfo.Body.Amount()
							}
							addNewAssetForAccount(tm.db, acct, im.Name, unitHash)
						}
					}
				}
				utxosToAdd = append(utxosToAdd, utxoInfo)
			} else {
				log.Warnf("Utxo of unit %v, message %v, output %v is already received\n", unitHash, messageID, i)
			}

		}
	case *structure.InvokeMessage:
		im := message.(*structure.InvokeMessage)

		for _, input := range im.Inputs {
			isMyAddress := false
			acct := addrmgr.DefaultAccountNum
			var err error
			tm.db.View(func(tx database.Tx) error {
				acct, isMyAddress, err = dbIsMyAddress(tx, input.GetAddress())
				if err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				if isMyAddress {
					log.Warn(" Unrecognized input account. ")
				}
				continue
			}
			if !isMyAddress {
				continue
			}
			err = updateAccountLastUsed(tm.db, input.GetAddress())
			if err != nil {
				log.Warn(errUpdateAccountFailed)
			}

			utxoKey := input.KeySerialize()
			utxoInfo := tm.utxoMgr.GetUTXOInfo(acct, utxoKey)
			if utxoInfo == nil {
				log.Warnf(errAlreadyReceivedUTXO)
			} else {
				tm.utxoMgr.RemoveUTXOInfoUnstable(utxoInfo)
				utxosToRemove = append(utxosToRemove, utxoInfo)
				for _, account := range tm.accounts {
					if account.AccountIndex == acct {
						for _, asset := range account.Assets {
							if hash.Equal(asset.AssetID, im.Asset) {
								asset.AssetBalance.TotalAmount -= utxoInfo.Body.Amount()
								if bytes.Equal(im.Asset, genesis.GenesisAsset) {
									tm.amount -= utxoInfo.Body.Amount()
								}
							}
						}
					}
				}
			}
		}

		for i, output := range im.Outputs {
			isMyAddress := false
			acct := uint32(1)
			var err error
			tm.db.View(func(tx database.Tx) error {
				acct, isMyAddress, err = dbIsMyAddress(tx, output.GetParam("addr"))
				return err
			})
			if err != nil {
				if isMyAddress {
					log.Warn(errUnrecognizedAccount)
				}
				continue
			}
			if !isMyAddress {
				continue
			}
			err = updateAccountLastUsed(tm.db, output.GetParam("addr"))
			if err != nil {
				log.Warn(errUpdateAccountFailed)
			}
			txUTXO := output.ToUtxo(im.Asset, unitHash, messageID, uint32(i))
			utxoInfo := &utxo.UnspentInfo{
				Account: acct,
				Body:    txUTXO,
			}

			if !tm.utxoMgr.HasUTXOInfo(acct, txUTXO.Key()) {
				for _, account := range tm.accounts {
					if account.AccountIndex == acct {
						hasAsset := false
						for _, asset := range account.Assets {
							if hash.Equal(asset.AssetID, im.Asset) {
								hasAsset = true
								asset.AssetBalance.TotalAmount += output.Amount
								asset.AssetBalance.PendingAmount += output.Amount
								if bytes.Equal(im.Asset, genesis.GenesisAsset) {
									tm.amount += output.Amount
									tm.pendingAmount += output.Amount
								}
							}
						}
						if !hasAsset {
							unitHashStr := fmt.Sprintf("%x", im.Asset)
							assetName := string([]byte(unitHashStr)[:6])
							if callback != nil {
								assetName, err = callback(im.Asset)
								if err != nil {
									log.Warn("Can't get assetName from gravity.")
								}
							}

							addNewAssetForAccount(tm.db, acct, assetName, im.Asset)

							newBalance := &Balance{
								TotalAmount:   utxoInfo.Body.Amount(),
								PendingAmount: utxoInfo.Body.Amount(),
							}

							newAsset := &WalletAsset{
								Name:         assetName,
								AssetID:      im.Asset,
								AssetBalance: newBalance,
							}
							account.Assets = append(account.Assets, newAsset)
						}
					}
				}
				utxosToAdd = append(utxosToAdd, utxoInfo)
			} else {
				log.Warnf("uTXO of unit %v, message %v, output %v is already received\n", unitHash, messageID, i)
			}
		}

	default:
		log.Warnf("This message is not a payment message\n")
	}
	mInfo := &messageInfo{
		msg:           message,
		messageID:     messageID,
		utxosToAdd:    utxosToAdd,
		utxosToRemove: utxosToRemove,
	}
	if tm.unstableMessages[hash.HashTypeS(unitHash)] != nil {
		tm.unstableMessages[hash.HashTypeS(unitHash)] = append(tm.unstableMessages[hash.HashTypeS(unitHash)], mInfo)
	} else {
		tm.unstableMessages[hash.HashTypeS(unitHash)] = []*messageInfo{mInfo}
	}
	log.Debug(" Balance : ", tm.amount, "   pending : ", tm.pendingAmount)
}

// UpdateStates change wallet uTXO states
func (tm *TXManager) UpdateStates(mci uint64, validUnits []hash.HashType, invalidUnits []hash.HashType, utxos []structure.Utxo) {
	log.Infof("update states with mci %d , validUnits count : %d  , invalidUnits count : %d  \n", mci, len(validUnits), len(invalidUnits))
	myMci := uint64(0xFFFFFFFFFFFFFFFF)
	err := tm.db.View(func(tx database.Tx) error {
		var err error
		myMci, err = walletdb.DbFetchLastMci(tx)
		return err
	})
	if err != nil {
		log.Errorf("Failed to get last mci of wallet\n")
		return
	}
	if mci != myMci+1 && !(mci == 0 && myMci == 0) {
		log.Warnf("Updating states on mci %v stops, since the last mci of wallet is %v\n", mci, myMci)
		return
	}

	utxosToAdd := make([]*utxo.UnspentInfo, 0)
	utxosToRemove := make([]*utxo.UnspentInfo, 0)
	validHashIndex := make([]hash.HashType, 0, len(tm.unstableMessages))
	validMsgInfoList := make([]*messageInfo, 0, len(tm.unstableMessages))
	for _, validUnit := range validUnits {
		messageInfos := tm.unstableMessages[hash.HashTypeS(validUnit)]
		if messageInfos == nil {
			continue
		}

		for _, messageInfo := range messageInfos {
			utxosToAdd = append(utxosToAdd, messageInfo.utxosToAdd...)
			for _, utxoInfo := range messageInfo.utxosToAdd {
				assetID := genesis.GenesisAsset
				switch info := utxoInfo.Body.(type) {
				case *structure.TxUtxo:
					assetID = info.Asset
				}
				for _, account := range tm.accounts {
					if account.AccountIndex == utxoInfo.Account {
						for _, asset := range account.Assets {
							if hash.Equal(asset.AssetID, assetID) {
								asset.AssetBalance.PendingAmount -= utxoInfo.Body.Amount()
								if bytes.Equal(assetID, genesis.GenesisAsset) {
									tm.pendingAmount -= utxoInfo.Body.Amount()
								}
							}
						}
					}
				}
			}
			utxosToRemove = append(utxosToRemove, messageInfo.utxosToRemove...)
			validHashIndex = append(validHashIndex, validUnit)
			validMsgInfoList = append(validMsgInfoList, messageInfo)
		}
		log.Info("update states   delete validUnit : ", validUnit)
		delete(tm.unstableMessages, hash.HashTypeS(validUnit))
	}

	for _, inValidUnit := range invalidUnits {
		messageInfos := tm.unstableMessages[hash.HashTypeS(inValidUnit)]
		if messageInfos == nil {
			continue
		}
		for _, messageInfo := range messageInfos {
			for _, utxoInfo := range messageInfo.utxosToRemove {
				assetID := make([]byte, 32)
				switch info := utxoInfo.Body.(type) {
				case *structure.TxUtxo:
					assetID = info.Asset
				}
				for _, account := range tm.accounts {
					if account.AccountIndex == utxoInfo.Account {
						for _, asset := range account.Assets {
							if hash.Equal(asset.AssetID, assetID) {
								asset.AssetBalance.TotalAmount += utxoInfo.Body.Amount()
								if bytes.Equal(assetID, genesis.GenesisAsset) {
									tm.amount += utxoInfo.Body.Amount()
								}
							}
						}
					}
				}
			}
			for _, utxoInfo := range messageInfo.utxosToAdd {
				assetID := make([]byte, 32)
				switch info := utxoInfo.Body.(type) {
				case *structure.TxUtxo:
					assetID = info.Asset
				}
				for _, account := range tm.accounts {
					if account.AccountIndex == utxoInfo.Account {
						for _, asset := range account.Assets {
							if hash.Equal(asset.AssetID, assetID) {
								asset.AssetBalance.TotalAmount -= utxoInfo.Body.Amount()
								asset.AssetBalance.PendingAmount -= utxoInfo.Body.Amount()
								if bytes.Equal(assetID, genesis.GenesisAsset) {
									tm.amount -= utxoInfo.Body.Amount()
									tm.pendingAmount -= utxoInfo.Body.Amount()
								}
							}
						}
					}
				}
			}
		}
		log.Info("update states   delete inValidUnit : ", inValidUnit)
		delete(tm.unstableMessages, hash.HashTypeS(inValidUnit))
	}
	for _, cmUtxo := range utxos {
		utxoInfo := &utxo.UnspentInfo{
			Account: addrmgr.DefaultAccountNum,
			Body:    cmUtxo,
		}
		switch utxo := cmUtxo.(type) {
		case *structure.CommissionUtxo:
		case *structure.ExternalUtxo:
			height := binary.BigEndian.Uint32(utxo.ExternalSource[32:36])
			log.Infof("receive a reward, amount: %d , block height: %d ", utxo.Amount(), height)
		}
		for _, account := range tm.accounts {
			if account.AccountIndex == utxoInfo.Account {
				for _, asset := range account.Assets {
					if hash.Equal(asset.AssetID, genesis.GenesisAsset) {
						asset.AssetBalance.TotalAmount += cmUtxo.Amount()
						tm.amount += cmUtxo.Amount()
					}
				}
			}
		}
		utxosToAdd = append(utxosToAdd, utxoInfo)
	}
	err = tm.db.Update(func(tx database.Tx) error {
		for _, utxoInfo := range utxosToAdd {
			err := tm.utxoMgr.AddUTXOInfoStable(tx, utxoInfo)
			if err != nil {
				log.Errorf("Failed to add utxo\n")
				return err
			}
		}
		for _, utxoInfo := range utxosToRemove {
			err := tm.utxoMgr.RemoveUTXOStable(tx, utxoInfo)
			if err != nil {
				log.Errorf("Failed to remove utxo\n")
				return err
			}
		}
		err := walletdb.DbPutLastMci(tx, mci)
		if err != nil {
			return err
		}
		timestamp := time.Now().Unix()
		for i, mInfo := range validMsgInfoList {
			err := tm.RecordMessage(tx, mInfo.msg, validHashIndex[i], mInfo.messageID, timestamp, mci)
			if err != nil {
				log.Errorf("Failed to record message of unit %v, messageID %v\n", validHashIndex[i], mInfo.messageID)
				return err
			}
			fmt.Println("record it")
		}
		return nil
	})
	if err != nil {
		log.Errorf("Failed to update states on mci %v\n", mci)
	}
	log.Debug(" Balance : ", tm.amount, "   pending : ", tm.pendingAmount)
}

// UpdateMCI change wallet uTXO states when DAG stable point increase
func (tm *TXManager) UpdateMCI(mci uint64,
	stableMessages []structure.Message, unitHashes []hash.HashType, messageIds []uint32, utxos []structure.Utxo, synced bool) {
	for i := range stableMessages {
		tm.ReceiveMessage(stableMessages[i], unitHashes[i], messageIds[i], nil)
	}
	invalidHashes := make([]hash.HashType, 0)
	tm.UpdateStates(mci, unitHashes, invalidHashes, utxos)
}

// GetBalance View the wallet asset details, and filter the designated asset details
// under designated accounts via account name and asset name
func (tm *TXManager) GetBalance(accountName, assetName string) ([]*walletrpc.AccountBalance, error) {
	balances := make([]*walletrpc.AccountBalance, 0)
	for _, acct := range tm.accounts {
		if strings.Compare(accountName, acct.Name) != 0 && strings.Compare(accountName, "") != 0 {
			continue
		}
		assets := make([]*walletrpc.AssetBalance, 0)
		for _, asset := range acct.Assets {
			if strings.Compare(assetName, asset.Name) != 0 && strings.Compare(assetName, "") != 0 {
				continue
			}
			bAsset := &walletrpc.AssetBalance{
				AssetName:        asset.Name,
				AssetTotal:       fmt.Sprintf("%d", asset.AssetBalance.TotalAmount),
				AssetSpendable:   fmt.Sprintf("%d", asset.AssetBalance.TotalAmount-asset.AssetBalance.PendingAmount),
				AssetUnconfirmed: fmt.Sprintf("%d", asset.AssetBalance.PendingAmount),
			}
			assets = append(assets, bAsset)
		}
		if len(assets) == 0 {
			return nil, fmt.Errorf(" can't find asset byassetName : %s ", assetName)
		}
		accountBalance := &walletrpc.AccountBalance{
			BalanceAccountName: acct.Name,
			BalanceAsset:       assets,
		}
		balances = append(balances, accountBalance)
	}
	if len(balances) == 0 {
		return nil, fmt.Errorf(" can't find account by accountName : %s ", accountName)
	}
	return balances, nil
}

// GetPaymentMessageInfo get payment message information with specified messageID
func (tm *TXManager) GetPaymentMessageInfo(unitHash hash.HashType, index uint32) (*structure.PaymentMessage, error) {
	messageKey := &MsgKey{
		unitHash: unitHash,
		id:       index,
	}
	message, err := dbFetchMessage(tm.db, messageKey)
	if err != nil {
		log.Error(" fetch message by messageKey failed : ", err)
		return nil, err
	}

	return message, nil
}

// RecordMessage save message to database
func (tm *TXManager) RecordMessage(tx database.Tx, msg structure.Message,
	unitHash hash.HashType, messageID uint32, timestamp int64, mci uint64) error {
	msgKey := &MsgKey{
		unitHash: unitHash,
		id:       messageID,
	}
	msgKeyBytes := msgKey.Serialize()
	msgBytes := msg.Serialize()
	msgValueBytes := make([]byte, 8+len(msgBytes))
	binary.BigEndian.PutUint64(msgValueBytes, uint64(timestamp))
	copy(msgValueBytes[8:], msgBytes)

	err := walletdb.DbPutMessage(tx, msgKeyBytes, msgValueBytes)
	if err != nil {
		return err
	}
	err = walletdb.DbPutMessageIndex(tx, mci, timestamp, msgKeyBytes)
	if err != nil {
		return err
	}
	return nil
}

// ListMessagesHistory Get transactions between from mci and to mci
func (tm *TXManager) ListMessagesHistory(from, to int64) ([]int64,
	[]*MsgKey, []structure.Message, error) {
	var timestamps []int64
	var messageKeyBytes [][]byte
	var messageListBytes [][]byte
	err := tm.db.View(func(tx database.Tx) error {
		var err error
		timestamps, messageKeyBytes, messageListBytes, err = walletdb.DbGetAllMessagesInRange(tx, from, to)
		return err
	})
	if err != nil {
		return nil, nil, nil, err
	}
	messageKeys := make([]*MsgKey, len(messageKeyBytes))
	messages := make([]structure.Message, len(messageListBytes))

	for i, msgKeyBytes := range messageKeyBytes {
		messageKeys[i] = new(MsgKey)
		messageKeys[i].Deserialize(msgKeyBytes)
	}

	for i, msgBytes := range messageListBytes {
		switch msgBytes[8] {
		case structure.PaymentMessageType:
			messages[i] = new(structure.PaymentMessage)
			messages[i].Deserialize(msgBytes[8:])
		case structure.IssueMessageType:
			messages[i] = new(structure.IssueMessage)
			messages[i].Deserialize(msgBytes[8:])
		case structure.InvokeMessageType:
			messages[i] = new(structure.InvokeMessage)
			messages[i].Deserialize(msgBytes[8:])
		default:
		}
	}
	return timestamps, messageKeys, messages, nil
}

// Serialize MsgKey serialize
func (mk *MsgKey) Serialize() []byte {
	messageKeyBytes := make([]byte, 32+4)
	copy(messageKeyBytes[0:32], mk.unitHash)
	binary.BigEndian.PutUint32(messageKeyBytes[32:], mk.id)
	return messageKeyBytes
}

// Deserialize MsgKey deserialize
func (mk *MsgKey) Deserialize(messageKeyBytes []byte) {
	mk.unitHash = messageKeyBytes[0:32]
	mk.id = binary.BigEndian.Uint32(messageKeyBytes[32:])

}

// dbFetchMessage fetch message from database
func dbFetchMessage(db database.DB, mk *MsgKey) (*structure.PaymentMessage, error) {
	var err error
	var mBytes []byte
	message := new(structure.PaymentMessage)
	err = db.View(func(tx database.Tx) error {
		mkBytes := mk.Serialize()
		mBytes, err = walletdb.DbFetchMessage(tx, mkBytes)
		if err != nil {
			return fmt.Errorf("message not found %v", err)
		}
		message.Deserialize(mBytes[8:])
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch message %v", err)
	}
	return message, nil
}

// updateAccountLastUsed update account last used address index
func updateAccountLastUsed(db database.DB, addrHash hash.HashType) error {
	err := db.Update(func(tx database.Tx) error {
		addrBytes, err := walletdb.DbFetchAddress(tx, addrHash)
		if err != nil {
			return err
		}
		addr, err := addrmgr.DecodeAddress(addrBytes)
		if err != nil {
			return err
		}
		acctBytes, err := walletdb.DbFetchAccountInfo(tx, addr.Account)
		if err != nil {
			return err
		}
		acctInfo := new(addrmgr.AccountInfo)
		err = acctInfo.DecodeAccountInfo(acctBytes)
		if err != nil {
			return err
		}
		if addr.Internal {
			if addr.Index > acctInfo.LastUsedInternalIndex {
				acctInfo.LastUsedInternalIndex = addr.Index
			}
		} else {
			if addr.Index > acctInfo.LastUsedExternalIndex {
				acctInfo.LastUsedExternalIndex = addr.Index
			}
		}

		newAcctInfoBytes, err := acctInfo.EncodeAccountInfo()
		if err != nil {
			return err
		}
		err = walletdb.DbPutAccountInfo(tx, addr.Account, newAcctInfoBytes)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

// dbFetchAccountInfo fetch account information from database
func dbFetchAccountInfo(db database.DB) ([]*addrmgr.AccountInfo, error) {
	var accounts [][]byte
	accts := make([]*addrmgr.AccountInfo, 0)
	err := db.View(func(tx database.Tx) error {
		var err error
		accounts, err = walletdb.DbFetchAllAccounts(tx)
		return err
	})
	if err != nil {
		return nil, err
	}
	for _, acctBytes := range accounts {
		acctInfo := new(addrmgr.AccountInfo)
		err = acctInfo.DecodeAccountInfo(acctBytes)
		if err != nil {
			log.Warn(" unmarshal accountInfo failed : ", err)
			continue
		}
		accts = append(accts, acctInfo)
	}
	return accts, nil
}

// dbFetchAssetName fetch asset name
func dbFetchAssetName(db database.DB, asset hash.HashType) (string, error) {

	var assetName []byte
	err := db.View(func(tx database.Tx) error {
		var err error
		assetName, err = walletdb.DbFetchAssetName(tx, asset)
		return err
	})
	if err != nil {
		return "", err
	}
	return string(assetName), nil
}

// dbIsMyAddress check  whether the specified address belongs to the wallet
func dbIsMyAddress(dbTx database.Tx, addrHash hash.HashType) (uint32, bool, error) {

	exist := dbTx.Data().Bucket([]byte("address")).KeyExists(addrHash)
	if exist {
		addrBytes, err := walletdb.DbFetchAddress(dbTx, addrHash)
		if err != nil {
			return 0, true, err
		}
		address, err := addrmgr.DecodeAddress(addrBytes)
		if err != nil {
			return 0, true, err
		}
		return address.Account, true, nil
	}
	return 0, false, nil
}

// addNewAssetForAccount add new asset to account information
func addNewAssetForAccount(db database.DB, acct uint32, name string, asset hash.HashType) error {

	err := db.Update(func(tx database.Tx) error {

		acctBytes, err := walletdb.DbFetchAccountInfo(tx, acct)
		if err != nil {
			return err
		}
		acctInfo := new(addrmgr.AccountInfo)
		err = acctInfo.DecodeAccountInfo(acctBytes)
		if err != nil {
			return err
		}
		acctInfo.AssetList = append(acctInfo.AssetList, asset)

		newAcctInfo, err := acctInfo.EncodeAccountInfo()
		err = walletdb.DbPutAccountInfo(tx, acct, newAcctInfo)
		if err != nil {
			return err
		}

		err = walletdb.DbPutAssetName(tx, asset, []byte(name))
		if err != nil {
			return err
		}

		err = walletdb.DbPutNameAsset(tx, []byte(name), asset)
		if err != nil {
			return err
		}

		return nil
	})

	return err
}

func dbFetchUTXO(db database.DB, uTXOKey []byte)(*structure.TxUtxo, error){

	var utxoValue []byte
	err := db.View(func(tx database.Tx) error {
		var err error
		utxoValue, err = walletdb.DbFetchUTXO(tx,uTXOKey)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	txUtxo := new(structure.TxUtxo)
	txUtxo.DeserializeFromKeyValue(uTXOKey, utxoValue)
	return txUtxo, nil
}

// isDoubleSpent 判断同一笔交易UTXO是否存在双花
func isDoubleSpent(sr *utxo.SelectResult, utxo *utxo.UnspentInfo) bool{
	for _,selectedUTXO := range sr.Utxos {
		if selectedUTXO == utxo{
			return true
		}
	}
	return false
}

func isAlreadySelectedAddress(sr *utxo.SelectResult, address hash.HashType) bool{
	for _,selectedAddress := range sr.Addresses {
		if hash.Equal(selectedAddress, address) {
			return true
		}
	}
	return false
}

//unMarshalIssueMessage
func unMarshalIssueMessage(issueJson []byte)(*structure.IssueMessage, error){
	issueMessage := new(structure.IssueMessage)
	err := json.Unmarshal(issueJson, issueMessage)
	if err != nil{
		return nil, fmt.Errorf(errUnmarshalFailed)
	}
	return issueMessage, nil
}

// unMarshalDeployMessage
func unMarshalDeployMessage(deployJson []byte)(*structure.DeployMessage, error){
	deployMessage := new(structure.DeployMessage)
	err := json.Unmarshal(deployJson, deployMessage)
	if err != nil{
		return nil, fmt.Errorf(errUnmarshalFailed)
	}
	return deployMessage, nil
}

// unMarshalInvokeMessage
func unMarshalInvokeMessage(invokeJson []byte)(*structure.InvokeMessage, error) {
	invokeMessage := new(structure.InvokeMessage)
	err := json.Unmarshal(invokeJson, invokeMessage)
	if err != nil {
		return nil, fmt.Errorf(errUnmarshalFailed)
	}
	return invokeMessage, nil
}