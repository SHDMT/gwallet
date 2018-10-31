package unitassemble

import (
	"github.com/SHDMT/gravity/platform/consensus/structure"
	"github.com/SHDMT/gwallet/platform/utxo"

	"github.com/SHDMT/gwallet/infrastructure/database"
	"github.com/SHDMT/gwallet/infrastructure/log"

	"encoding/binary"
	"errors"
	"fmt"
	"github.com/SHDMT/crypto/bliss"
	"github.com/SHDMT/crypto/secp256k1"
	"github.com/SHDMT/crypto/asymmetric"
	"github.com/SHDMT/gravity/infrastructure/crypto/hash"
	"github.com/SHDMT/gravity/platform/consensus/genesis"
	"github.com/SHDMT/gravity/platform/messagevalidator"
	"github.com/SHDMT/gwallet/platform/addrmgr"
	"github.com/SHDMT/gwallet/platform/dag"
	"github.com/SHDMT/gwallet/platform/message"
	"github.com/SHDMT/gwallet/platform/walletdb"
)

// Define error string
var (
	ErrUnSupportAlgorithm = " unsupported algorithm"
	ErrFetchPrivateKeyFailed = " get privateKey from database failed "
	ErrDecodedPrivateKey = errors.New("failed to get decode private key with bytes")
)

// UnitAssemble all the information needed to support UnitAssemble
type UnitAssemble struct {
	db         database.DB
	utxoMgr    *utxo.UnspentManager
	addrMgr    *addrmgr.AddressManager
	messageMgr *message.TXManager
	dagClient  *dag.GravityClient
	cryptoKey  *addrmgr.CryptoKey
}

// NewUnitAssemble create a new UnitAssemble instance
func NewUnitAssemble(db database.DB, utxoMgr *utxo.UnspentManager,
	addrMgr *addrmgr.AddressManager, messageMgr *message.TXManager,
	dagClient *dag.GravityClient, cryptoKey *addrmgr.CryptoKey) *UnitAssemble {

	return &UnitAssemble{
		db:         db,
		utxoMgr:    utxoMgr,
		addrMgr:    addrMgr,
		messageMgr: messageMgr,
		dagClient:  dagClient,
		cryptoKey:  cryptoKey,
	}
}

// CalculateCommission create unit and calculate commission , but not send the unit to gravity network
func (ua *UnitAssemble) CalculateCommission(args interface{}) (uint64, error) {

	_, commission, err := ua.createUnit(nil, args, false)
	if err != nil {
		log.Errorf("Failed to create unit : %s", err.Error())
		return 0, err
	}
	return commission, nil
}

// CreateUnit create unit and send the unit to gravity network
func (ua *UnitAssemble) CreateUnit(args interface{}) (hash.HashType, error) {

	unitTemplate, err := ua.dagClient.GetUnitTemplate()
	if err != nil {
		log.Errorf("Failed to get unit template from gravity: %s\n", err)
		return nil, err
	}

	unitTemplate.ContentHash = nil
	unit, _, err := ua.createUnit(unitTemplate, args, true)
	if err != nil {
		log.Errorf("Failed to create unit : %s", err.Error())
		return nil, err
	}
	err = ua.dagClient.PostUnit(unit)
	if err != nil {
		log.Errorf("Failed to post the unit %v", unitTemplate.Hash())
		return nil, err
	}
	return unitTemplate.Hash(), nil
}

func (ua *UnitAssemble) createUnit(unitTemplate *structure.Unit, args interface{}, send bool) (*structure.Unit, uint64, error) {
	//Version + Alt + LastBall + LastKeyUnit + Timestamp + (parentNum + parents) + authorNum + messageNum
	headerSizeWithoutAuthors := 4 + 1 + 32 + 32 + 8 + 1 + 64 + 1 + 1 //144bytes
	commission := uint64(headerSizeWithoutAuthors)
	var result *utxo.SelectResult

	messages := make([]structure.Message, 0)
	privKeys := make([]asymmetric.PrivateKey, 0)
	asset := genesis.GenesisAsset
	acct := addrmgr.DefaultAccountNum
	switch arg := args.(type) {
	case *message.PaymentARGS:
		var err error
		acct, err = getAccountByName(ua.db, arg.AccountName)
		if err != nil {
			return nil, 0, err
		}
		var pm *structure.PaymentMessage
		param := utxo.PickerParam{
			Account:          acct,
			Asset:            asset,
			SelectCommission: true,
		}
		var changeAddress *addrmgr.Address
		pm, result, changeAddress, err = ua.messageMgr.CreatePaymentMessage(ua.cryptoKey, arg.SendPairs, commission, param)
		if err != nil {
			return nil, 0, err
		}
		if changeAddress != nil {
			ua.dagClient.UpdateAddress(*changeAddress)
		}

		privKeys = append(privKeys, result.PrivateKeys...)
		messages = append(messages, pm)

	case *message.TextARGS:
		var err error
		acct, err = getAccountByName(ua.db, arg.AccountName)
		if err != nil {
			return nil, 0, err
		}

		tm, err := ua.messageMgr.CreateTextMessage(arg.Text)
		if err != nil {
			return nil, 0, err
		}
		commission += 4 + 1 + 1 + 4 + 32 + 4 + uint64(len([]byte(arg.Text)))
		var pm *structure.PaymentMessage
		param := utxo.PickerParam{
			Account:          acct,
			Asset:            asset,
			SelectCommission: true,
		}
		var changeAddress *addrmgr.Address
		pm, result, changeAddress, err = ua.messageMgr.CreatePaymentMessage(ua.cryptoKey, nil, commission, param)
		if err != nil {
			return nil, 0, err
		}
		if changeAddress != nil {
			ua.dagClient.UpdateAddress(*changeAddress)
		}

		privKeys = append(privKeys, result.PrivateKeys...)
		messages = append(messages, tm)
		messages = append(messages, pm)

	case *message.InvokeARGS:
		var err error
		acct, err = getAccountByName(ua.db, arg.AccountName)
		if err != nil {
			return nil, 0, err
		}

		var im *structure.InvokeMessage
		var invokePrivKeys []asymmetric.PrivateKey
		var sourceInfo *utxo.SelectResult
		param := utxo.PickerParam{
			Account:          acct,
			Asset:            arg.Asset,
			SelectCommission: true,
		}
		var changeAddress *addrmgr.Address
		log.Debugf(" invoke param : %x \n", arg.Params)
		im, sourceInfo, changeAddress, err = ua.messageMgr.CreateInvokeMessage(arg, ua.cryptoKey, commission, param)
		if err != nil {
			return nil, 0, err
		}
		if changeAddress != nil {
			ua.dagClient.UpdateAddress(*changeAddress)
		}

		invokePrivKeys = sourceInfo.PrivateKeys
		commission += 4 + uint64(len(im.Serialize()))
		for _, pk := range invokePrivKeys {
			switch pk.(type) {
			case *bliss.PrivateKey:
				commission += utxo.BlissAuthorBytes
			case *secp256k1.PrivateKey:
				commission += utxo.Secp256k1AuthorBytes
			default:
				panic(ErrUnSupportAlgorithm)
			}
		}

		var pm *structure.PaymentMessage
		if len(sourceInfo.CmGroups) != 0 {
			param.SelectCommission = false
		}
		if len(sourceInfo.Utxos) != 0 {
			param.ExcludedUTXO = sourceInfo.Utxos
		}
		param.Account = addrmgr.DefaultAccountNum
		param.Asset = genesis.GenesisAsset
		var payChange *addrmgr.Address
		pm, result, payChange, err = ua.messageMgr.CreatePaymentMessage(ua.cryptoKey, nil, commission, param)
		if err != nil {
			return nil, 0, err
		}
		if payChange != nil {
			ua.dagClient.UpdateAddress(*payChange)
		}
		privKeys = append(privKeys, invokePrivKeys...)
		privKeys = append(privKeys, result.PrivateKeys...)
		messages = append(messages, im)
		messages = append(messages, pm)

	case *message.IssueARGS:
		var err error
		acct, err = getAccountByName(ua.db, arg.AccountName)
		if err != nil {
			return nil, 0, err
		}

		if arg.PublisherAddress == nil {
			addr, err := ua.addrMgr.NewAddress("default", true)
			if err != nil {
				log.Errorf(" set publisher address failed ,can't get a new address ")
				return nil, 0, fmt.Errorf(" set publisher address failed ,can't get a new address : %s ", err)
			}
			privKeyBytes, _, err := utxo.FetchPrivKey(ua.db, addr.Address, ua.cryptoKey)
			if err != nil {
				log.Errorf(ErrFetchPrivateKeyFailed)
				return nil, 0, fmt.Errorf(ErrFetchPrivateKeyFailed)
			}
			worker := secp256k1.NewCipherSuite()
			publisherPrivKey, err := worker.UnmarshalPrivateKey(privKeyBytes)
			if err != nil {
				return nil, 0, ErrDecodedPrivateKey
			}
			privKeys = append(privKeys, publisherPrivKey)
			arg.PublisherAddress = addr.Address
			commission += utxo.Secp256k1AuthorBytes
		} else {
			privKeyBytes, algType, err := utxo.FetchPrivKey(ua.db, arg.PublisherAddress, ua.cryptoKey)
			if err != nil {
				log.Errorf(ErrFetchPrivateKeyFailed)
				return nil, 0, fmt.Errorf(ErrFetchPrivateKeyFailed)
			}
			var worker asymmetric.CipherSuite
			if algType == addrmgr.BLISS{
				worker = bliss.NewCipherSuite()
				commission += utxo.BlissAuthorBytes
			}else if algType == addrmgr.SECP256K1{
				worker = secp256k1.NewCipherSuite()
				commission += utxo.Secp256k1AuthorBytes
			}else {
				panic(ErrUnSupportAlgorithm)
			}
			publisherPrivKey, err := worker.UnmarshalPrivateKey(privKeyBytes)
			if err != nil {
				return nil, 0, ErrDecodedPrivateKey
			}
			privKeys = append(privKeys, publisherPrivKey)
		}

		im, err := ua.messageMgr.CreateIssueMessage(arg)

		commission += 4 + uint64(len(im.Serialize()))
		var pm *structure.PaymentMessage
		excludedAddress := make([]hash.HashType, 0)
		excludedAddress = append(excludedAddress, arg.PublisherAddress)
		param := utxo.PickerParam{
			Account:          acct,
			Asset:            asset,
			SelectCommission: true,
			ExcludedAddress:  excludedAddress,
		}
		var changeAddress *addrmgr.Address
		pm, result, changeAddress, err = ua.messageMgr.CreatePaymentMessage(ua.cryptoKey, nil, commission, param)
		if err != nil {
			return nil, 0, err
		}
		if changeAddress != nil {
			ua.dagClient.UpdateAddress(*changeAddress)
		}
		privKeys = append(privKeys, result.PrivateKeys...)
		messages = append(messages, im)
		messages = append(messages, pm)

	case *message.DeployARGS:
		var err error
		acct, err = getAccountByName(ua.db, arg.AccountName)
		if err != nil {
			return nil, 0, err
		}
		hasOfficialAddr := false
		var officialAddress hash.HashType
		
		for _, address := range messagevalidator.OfficialAddresses {
			privKeyBytes, _, err := utxo.FetchPrivKey(ua.db, address, ua.cryptoKey)
			if err != nil {
				continue
			}
			hasOfficialAddr = true
			worker := secp256k1.NewCipherSuite()
			publisherPrivKey, err := worker.UnmarshalPrivateKey(privKeyBytes)
			if err != nil {
				return nil, 0, ErrDecodedPrivateKey
			}
			officialAddress = address
			privKeys = append(privKeys, publisherPrivKey)
			break
		}
		if !hasOfficialAddr {
			log.Errorf(" You have no authority to publish deploy pm")
			return nil, 0, fmt.Errorf("you have no authority to publish deploy pm")
		}
		dm, err := ua.messageMgr.CreateDeployMessage(arg.Contracts)

		commission += 4 + uint64(len(dm.Serialize())) + 182 //official author
		var pm *structure.PaymentMessage
		excludedAddress := make([]hash.HashType, 0)
		excludedAddress = append(excludedAddress, officialAddress)
		param := utxo.PickerParam{
			Account:          acct,
			Asset:            asset,
			SelectCommission: true,
			ExcludedAddress:  excludedAddress,
		}
		var changeAddress *addrmgr.Address
		pm, result, changeAddress, err = ua.messageMgr.CreatePaymentMessage(ua.cryptoKey, nil, commission, param)
		if err != nil {
			return nil, 0, err
		}
		if changeAddress != nil {
			ua.dagClient.UpdateAddress(*changeAddress)
		}

		privKeys = append(privKeys, result.PrivateKeys...)
		messages = append(messages, dm)
		messages = append(messages, pm)

	case *message.InvokeWithJsonArgs:
		log.Debug(" -----------> unitAssemble invokeContractWithJson")
		var err error
		acct, err = getAccountByName(ua.db, arg.PaymentAccount)
		if err != nil {
			return nil, 0, err
		}

		var im *structure.InvokeMessage
		var invokePrivKeys []asymmetric.PrivateKey
		var sourceInfo *utxo.SelectResult
		var changeAddress *addrmgr.Address
		im,sourceInfo, changeAddress, err = ua.messageMgr.CreateInvokeMessageWithJson(acct,arg.InvokeAmount,arg.InvokeJson, ua.cryptoKey)
		if err != nil {
			return nil, 0, err
		}
		if changeAddress != nil {
			log.Debugf(" invoke pm update address : %x \n", changeAddress.Address)
			ua.dagClient.UpdateAddress(*changeAddress)
		}

		invokePrivKeys = sourceInfo.PrivateKeys
		log.Debugf(" invoke privkey num : %d \n", len(invokePrivKeys))

		commission += 4 + uint64(len(im.Serialize()))
		for _, pk := range invokePrivKeys {
			switch pk.(type) {
			case *bliss.PrivateKey:
				commission += utxo.BlissAuthorBytes
			case *secp256k1.PrivateKey:
				commission += utxo.Secp256k1AuthorBytes
			default:
				panic(ErrUnSupportAlgorithm)
			}
		}

		var pm *structure.PaymentMessage
		param := utxo.PickerParam{
			Account:          acct,
			Asset:            genesis.GenesisAsset,
			SelectCommission: true,
		}
		if len(sourceInfo.CmGroups) != 0 {
			param.SelectCommission = false
		}
		if len(sourceInfo.Utxos) != 0 {
			param.ExcludedUTXO = sourceInfo.Utxos
		}
		param.Asset = genesis.GenesisAsset
		var paychange *addrmgr.Address
		pm, result, paychange, err = ua.messageMgr.CreatePaymentMessage(ua.cryptoKey, nil, commission, param)
		if err != nil {
			return nil, 0, err
		}
		if paychange != nil {
			log.Debugf(" invoke pm update address : %x \n", changeAddress.Address)
			ua.dagClient.UpdateAddress(*paychange)
		}
		log.Debugf(" payments privKey num : %d \n", len(result.PrivateKeys))

		privKeys = append(privKeys, invokePrivKeys...)
		privKeys = append(privKeys, result.PrivateKeys...)
		messages = append(messages, im)
		messages = append(messages, pm)

	case *message.IssueWithJsonArgs:
		log.Debug(" send issue pm ")
		var err error
		acct, err = getAccountByName(ua.db, arg.PaymentAccount)
		if err != nil {
			return nil, 0, err
		}
		var im *structure.IssueMessage
		var publisherPrivateKey asymmetric.PrivateKey
		im,publisherPrivateKey,commission, err = ua.messageMgr.CreateIssueMessageWithJson(arg.IssueJson,commission,ua.cryptoKey)
		if err != nil {
			return nil, 0, err
		}
		privKeys = append(privKeys, publisherPrivateKey)

		commission += 4 + uint64(len(im.Serialize()))
		var pm *structure.PaymentMessage
		excludedAddress := make([]hash.HashType, 0)
		excludedAddress = append(excludedAddress, im.PublisherAddress)
		param := utxo.PickerParam{
			Account:          acct,
			Asset:            asset,
			SelectCommission: true,
			ExcludedAddress:  excludedAddress,
		}
		var changeAddress *addrmgr.Address
		pm, result, changeAddress, err = ua.messageMgr.CreatePaymentMessage(ua.cryptoKey, nil, commission, param)
		if err != nil {
			return nil, 0, err
		}
		if changeAddress != nil {
			log.Debugf(" issue pm update address : %x \n", changeAddress.Address)
			ua.dagClient.UpdateAddress(*changeAddress)
		}
		privKeys = append(privKeys, result.PrivateKeys...)
		messages = append(messages, im)
		messages = append(messages, pm)

	case *message.DeployWithJsonArgs:
		log.Debug(" send deploy pm ")
		var err error
		acct, err = getAccountByName(ua.db, arg.PaymentAccount)
		if err != nil {
			return nil, 0, err
		}
		hasOfficialAddr := false
		var officialAddress hash.HashType

		for _, address := range messagevalidator.OfficialAddresses {
			privKeyBytes, _, err := utxo.FetchPrivKey(ua.db, address, ua.cryptoKey)
			if err != nil {
				continue
			}
			hasOfficialAddr = true
			worker := secp256k1.NewCipherSuite()
			publisherPrivKey, err := worker.UnmarshalPrivateKey(privKeyBytes)
			if err != nil {
				return nil, 0, ErrDecodedPrivateKey
			}
			officialAddress = address
			privKeys = append(privKeys, publisherPrivKey)
			break
		}
		if !hasOfficialAddr {
			log.Errorf(" You have no authority to publish deploy pm")
			return nil, 0, fmt.Errorf("you have no authority to publish deploy pm")
		}
		dm, err := ua.messageMgr.CreateDeployMessageWithJson(arg.DeployJson)

		commission += 4 + uint64(len(dm.Serialize())) + 182 //official author
		var pm *structure.PaymentMessage
		excludedAddress := make([]hash.HashType, 0)
		excludedAddress = append(excludedAddress, officialAddress)
		param := utxo.PickerParam{
			Account:          acct,
			Asset:            asset,
			SelectCommission: true,
			ExcludedAddress:  excludedAddress,
		}
		var changeAddress *addrmgr.Address
		pm, result, changeAddress, err = ua.messageMgr.CreatePaymentMessage(ua.cryptoKey, nil, commission, param)
		if err != nil {
			return nil, 0, err
		}
		if changeAddress != nil {
			log.Debugf(" deploy pm update address : %x \n", changeAddress.Address)
			ua.dagClient.UpdateAddress(*changeAddress)
		}
		log.Debugf(" payments privKey num : %d \n", len(result.PrivateKeys))

		privKeys = append(privKeys, result.PrivateKeys...)
		messages = append(messages, dm)
		messages = append(messages, pm)

	}
	if !send {
		return nil, result.Commission, nil
	}

	unitTemplate.Messages = messages
	unitTemplate.Authors = make([]*structure.Author, 0, len(privKeys))
	authorMap := make(map[string]asymmetric.PrivateKey)

	var worker asymmetric.CipherSuite
	for _, privKey := range privKeys {
		def := []byte{0}
		switch privKey.(type) {
		case *bliss.PrivateKey:
			worker = bliss.NewCipherSuite()
			def[0] = byte(1)
		case *secp256k1.PrivateKey:
			worker = secp256k1.NewCipherSuite()
		default:
			panic(ErrUnSupportAlgorithm)
		}
		pubKey := privKey.Public()
		pubkeyBytes, err := worker.MarshalPublicKey(pubKey)

		if err != nil {
			log.Errorf("Failed to marshal public key\n")
			return nil, 0, err
		}
		def = append(def, pubkeyBytes...)
		author := new(structure.Author)
		author.Definition = def
		addr := hash.Sum256(def[1:])
		author.Address = addr
		if authorMap[string(addr)] != nil {
			log.Debugf("duplicate private")
			continue
		}
		authorMap[string(addr)] = privKey
		unitTemplate.Authors = append(unitTemplate.Authors, author)
	}
	hashToSign := unitTemplate.GetHashToSign()
	for _, author := range unitTemplate.Authors {
		var sign []byte
		privKey := authorMap[string(author.Address)]
		switch privKey.(type) {
		case *bliss.PrivateKey:
			sign = make([]byte, utxo.BlissSignBytes)
		case *secp256k1.PrivateKey:
			sign = make([]byte, utxo.Secp256k1SignBytes)
		default:
			panic(ErrUnSupportAlgorithm)
		}
		sig, err := privKey.Sign(hashToSign)
		if err != nil {
			log.Errorf("Failed to sign the unit\n")
			return nil, 0, err
		}
		sigLen := len(sig)
		copy(sign[:sigLen], sig)
		author.Authentifiers = sign
	}
	return unitTemplate, result.Commission, nil
}

// getAccountByName get account index by account name
func getAccountByName(db database.DB, acctName string) (uint32, error) {

	acct := addrmgr.DefaultAccountNum
	if acctName != "" {
		var acctBytes []byte
		var err error
		db.View(func(tx database.Tx) error {
			acctBytes, err = walletdb.DbFetchAccount(tx, []byte(acctName))
			return err
		})

		if err != nil {
			errStr := fmt.Sprintf(" can't find account : %s ", acctName)
			return 0, errors.New(errStr)
		}
		acct = uint32(binary.BigEndian.Uint32(acctBytes))
	}

	return acct, nil
}
