package walletdb

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/SHDMT/gravity/infrastructure/crypto/hash"
	"github.com/SHDMT/gwallet/infrastructure/database"
	e "github.com/SHDMT/gwallet/infrastructure/errors"
	"github.com/SHDMT/gwallet/infrastructure/log"
	"github.com/SHDMT/gwallet/platform/walletdb/internal/dbnamespace"
	"github.com/pkg/errors"
	"math"
	"time"
)

//DbPutKeyPairs put in bucket,key:publicKey,value:privateKey
func DbPutKeyPairs(dbTx database.Tx, publicKey []byte,
	privateKey []byte) error {

	keyPairsBucket := dbTx.Data().Bucket(dbnamespace.KeyPairsBucket)

	return keyPairsBucket.Put(publicKey, privateKey)
}

//DbFetchPrivateKey fetch privateKey from bucket by publicKey
func DbFetchPrivateKey(dbTx database.Tx, publicKey []byte) ([]byte, error) {
	keyPairsBucket := dbTx.Data().Bucket([]byte(dbnamespace.KeyPairsBucket))

	privateKey := keyPairsBucket.Get(publicKey)
	errString := "privateKey is not found from DB"
	privateKeyExistErr := e.NewWalletError(e.ErrNotFoundFormDB, errString, nil)
	if privateKey == nil {
		return nil, privateKeyExistErr
	}
	return privateKey, nil
}

//DbPutAddrPub put in bucket,key:addressHash,value:publicKey
func DbPutAddrPub(dbTx database.Tx, addrHash hash.HashType,
	publicKey []byte) error {

	addrPubBucket := dbTx.Data().Bucket(dbnamespace.AddrPubBucket)

	return addrPubBucket.Put(addrHash, publicKey)
}

//DbPutAddress put in bucket,key:addressHash,value:encodeAddress
func DbPutAddress(dbTx database.Tx, addrHash hash.HashType,
	encodeAddr []byte) error {

	addressBucket := dbTx.Data().Bucket(dbnamespace.AddressBucket)

	return addressBucket.Put(addrHash, encodeAddr)
}

//DbFetchPublicKey fetch publicKey from bucket by addressHash
func DbFetchPublicKey(dbTx database.Tx, addrHash hash.HashType) ([]byte, error) {

	addrPubBucket := dbTx.Data().Bucket([]byte(dbnamespace.AddrPubBucket))

	publicKey := addrPubBucket.Get(addrHash)
	errString := "publicKey is not found from DB"
	publicKeyExistErr := e.NewWalletError(e.ErrNotFoundFormDB, errString, nil)
	if publicKey == nil {
		return nil, publicKeyExistErr
	}
	return publicKey, nil
}

//DbFetchAddress fetch encodeAddress from bucket by addressHash
func DbFetchAddress(dbTx database.Tx, addrHash hash.HashType) ([]byte, error) {

	addressBucket := dbTx.Data().Bucket([]byte(dbnamespace.AddressBucket))

	addressBytes := addressBucket.Get(addrHash)
	errString := "address is not found from DB"
	addressExistErr := e.NewWalletError(e.ErrNotFoundFormDB, errString, nil)

	if addressBytes == nil {
		return nil, addressExistErr
	}
	return addressBytes, nil
}

//DbListAllMyAddress list all my address from AddressBucket
func DbListAllMyAddress(dbTx database.Tx) ([][]byte, error) {

	addresses := make([][]byte, 0)
	addressBucket := dbTx.Data().Bucket([]byte(dbnamespace.AddressBucket))
	err := addressBucket.ForEach(func(_, v []byte) error {
		addresses = append(addresses, v)
		return nil
	})
	return addresses, err
}

//DbPutAccount put in bucket,key:name,value:accountIndex
func DbPutAccount(dbTx database.Tx, name []byte, accountIndex uint32) error {

	accountBucket := dbTx.Data().Bucket(dbnamespace.AccountBucket)

	accountBytes := make([]byte, 8)
	binary.BigEndian.PutUint32(accountBytes, accountIndex)
	err := accountBucket.Put(name, accountBytes)
	if err != nil {
		log.Errorf("Failed to put account ")
		return errors.WithMessage(err, "Failed to put account")
	}
	return nil
}

//DbFetchAccount fetch accountIndex from bucket by name
func DbFetchAccount(dbTx database.Tx, name []byte) ([]byte, error) {

	accountBucket := dbTx.Data().Bucket(dbnamespace.AccountBucket)
	errString := "Account not found"
	accountErr := e.NewWalletError(e.ErrNotFoundFormDB,
		errString, nil)
	account := accountBucket.Get(name)
	if account == nil {
		return nil, accountErr
	}

	return account, nil
}

//DbHasAccount  this data if or not exists in the bucket
func DbHasAccount(dbTx database.Tx, name []byte) bool {

	accountBucket := dbTx.Data().Bucket(dbnamespace.AccountBucket)

	return accountBucket.KeyExists(name)
}

//CreateWalletBucket create bucket
func CreateWalletBucket(db database.DB) error {
	err := db.Update(func(tx database.Tx) error {
		errs := make([]error, 20)
		_, errs[0] = tx.Data().CreateBucket(dbnamespace.KeyPairsBucket)
		_, errs[1] = tx.Data().CreateBucket(dbnamespace.AddrPubBucket)
		_, errs[2] = tx.Data().CreateBucket(dbnamespace.AddressBucket)
		_, errs[3] = tx.Data().CreateBucket(dbnamespace.MessageBucket)
		_, errs[4] = tx.Data().CreateBucket(dbnamespace.MessageIndexBucket)
		_, errs[5] = tx.Data().CreateBucket(dbnamespace.UtxoBucket)
		_, errs[6] = tx.Data().CreateBucket(dbnamespace.LastMciBucket)

		_, errs[7] = tx.Data().CreateBucket(dbnamespace.MasterKeyBucket)
		_, errs[8] = tx.Data().CreateBucket(dbnamespace.CryptoKeyBucket)
		_, errs[9] = tx.Data().CreateBucket(dbnamespace.CoinTypeKeyBucket)
		_, errs[10] = tx.Data().CreateBucket(dbnamespace.AccountInfoBucket)
		_, errs[11] = tx.Data().CreateBucket(dbnamespace.AccountBucket)
		_, errs[12] = tx.Data().CreateBucket(dbnamespace.AccountNameBucket)
		_, errs[14] = tx.Data().CreateBucket(dbnamespace.LastAccountBucket)
		_, errs[15] = tx.Data().CreateBucket(dbnamespace.LastUsedAccountBucket)
		_, errs[16] = tx.Data().CreateBucket(dbnamespace.SecretKeyBucket)
		_, errs[17] = tx.Data().CreateBucket(dbnamespace.AssetBucket)
		_, errs[18] = tx.Data().CreateBucket(dbnamespace.AssetNameBucket)
		_, errs[19] = tx.Data().CreateBucket(dbnamespace.NameAssetBucket)

		for _, err := range errs {
			if err != nil {
				log.Errorf("create bucket err : %v\n", err)
				return err
			}
		}
		log.Debug(" put mci 0 to lastMci")
		err := DbPutLastMci(tx, uint64(0))
		if err != nil {
			log.Errorf("LastMci插入数据库出错%v", err)
		}
		return nil
	})
	return err
}

//DbPutMessageIndex put in bucket,key:mci+messageKeyBytes,value:timestamp
func DbPutMessageIndex(dbTx database.Tx, mci uint64, timestamp int64, messageKeyBytes []byte) error {
	messageIndexBucket := dbTx.Data().Bucket(dbnamespace.MessageIndexBucket)
	mciKeyBytes := make([]byte, 8+len(messageKeyBytes))
	binary.BigEndian.PutUint64(mciKeyBytes, mci)
	copy(mciKeyBytes[8:], messageKeyBytes)

	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timestamp))

	return messageIndexBucket.Put(mciKeyBytes, timeBytes)
}

//DbGetAllMessagesInRange get all messages by mci
func DbGetAllMessagesInRange(dbTx database.Tx, from int64, to int64) ([]int64, [][]byte, [][]byte, error) {
	messageIndexBucket := dbTx.Data().Bucket(dbnamespace.MessageIndexBucket)
	messageBucket := dbTx.Data().Bucket(dbnamespace.MessageBucket)
	fromBytes := make([]byte, 8+32+4)
	toBytes := make([]byte, 8+32+4)
	for i := 0; i < 44; i++ {
		toBytes[i] = 0xFF
	}

	binary.BigEndian.PutUint64(fromBytes, uint64(from))
	binary.BigEndian.PutUint64(toBytes, uint64(to))

	timestamps := make([]int64, 0, 1024)
	messageKeys := make([][]byte, 0, 1024)

	messageIndexBucket.ForEachInRange(fromBytes, toBytes, func(k, v []byte) error {
		timestamps = append(timestamps, int64(binary.BigEndian.Uint64(v)))
		messageKeys = append(messageKeys, k[8:])
		return nil
	})
	messageListBytes := make([][]byte, len(messageKeys))
	for i, msgKey := range messageKeys {
		messageBytes := messageBucket.Get(msgKey)
		errString := "messages is not found from DB"
		messagesExistErr := e.NewWalletError(e.ErrNotFoundFormDB, errString, nil)

		if messageBytes == nil {
			return nil, nil, nil, messagesExistErr
		}
		messageListBytes[i] = messageBytes
	}

	return timestamps, messageKeys, messageListBytes, nil
}

//DbPutMessage put in bucket,key:messageKeyBytes,value:messageBytes
func DbPutMessage(dbTx database.Tx, messageKeyBytes []byte,
	messageBytes []byte) error {
	messageBucket := dbTx.Data().Bucket(dbnamespace.MessageBucket)

	return messageBucket.Put(messageKeyBytes, messageBytes)
}

//DbFetchMessage fetch messageBytes from bucket by messageKeyBytes
func DbFetchMessage(dbTx database.Tx, messageKeyBytes []byte) ([]byte, error) {

	messageBucket := dbTx.Data().Bucket([]byte(dbnamespace.MessageBucket))

	messageBytes := messageBucket.Get(messageKeyBytes)
	if messageBytes == nil {
		return nil, fmt.Errorf("message not found ")
	}
	return messageBytes, nil
}

//DbPutLastMci put in bucket,key:[]byte{0, 0, 0, 0, 0, 0, 0, 0},value:lastMci
func DbPutLastMci(dbTx database.Tx, lastMci uint64) error {

	lastMciBucket := dbTx.Data().Bucket(dbnamespace.LastMciBucket)

	lastMciBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lastMciBytes, lastMci)

	return lastMciBucket.Put(dbnamespace.LastMciKey, lastMciBytes)
}

//DbFetchLastMci fetch lastMci from bucket by LastMciKey
func DbFetchLastMci(dbTx database.Tx) (uint64, error) {

	lastMciBucket := dbTx.Data().Bucket([]byte(dbnamespace.LastMciBucket))

	lastMciBytes := lastMciBucket.Get(dbnamespace.LastMciKey)
	if lastMciBytes == nil {
		return math.MaxUint64, fmt.Errorf("lastMci not found ")
	}

	lastMci := uint64(binary.BigEndian.Uint64(lastMciBytes))

	return lastMci, nil
}

//DbFetchAllUtxos get all utxos from UtxoBucket
func DbFetchAllUtxos(dbTx database.Tx) (utxoKeys, utxoValues [][]byte, err error) {
	txUtxoBucket := dbTx.Data().Bucket(dbnamespace.UtxoBucket)
	utxoKeys = make([][]byte, 0, 1024)
	utxoValues = make([][]byte, 0, 1024)
	err = nil

	txUtxoBucket.ForEach(func(k, v []byte) error {
		utxoKeys = append(utxoKeys, k)
		utxoValues = append(utxoValues, v)
		return nil
	})
	return
}

// DbFetchUTXO fetch unspent by specified utxoKey
func DbFetchUTXO(dbTx database.Tx, utxoKey []byte) ([]byte, error){
	utxoBucket := dbTx.Data().Bucket(dbnamespace.UtxoBucket)
	uTXOValue := utxoBucket.Get(utxoKey)
	if uTXOValue == nil {
		log.Errorf("UTXO not found %v\n", uTXOValue)
		return nil, errors.New("UTXO not found")
	}
	return uTXOValue, nil
}

//DbAddUtxo add utxo to database
func DbAddUtxo(dbTx database.Tx, utxoKey, utxoValue []byte) error {
	utxoBucket := dbTx.Data().Bucket(dbnamespace.UtxoBucket)
	return utxoBucket.Put(utxoKey, utxoValue)
}

//DbRemoveUtxo remove utxo
func DbRemoveUtxo(dbTx database.Tx, utxoKey []byte) error {
	utxoBucket := dbTx.Data().Bucket(dbnamespace.UtxoBucket)
	return utxoBucket.Delete(utxoKey)
}

//RecordUpdateTime record database latest open time
func RecordUpdateTime(db database.DB) error {
	timestamp := time.Now().Unix()
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timestamp))
	return db.Update(func(tx database.Tx) error {
		return tx.Data().Put(dbnamespace.UpdateKey, timeBytes)
	})
}

//PrintDBWithBase64 
func PrintDBWithBase64(db database.DB, bucketName []byte) {
	fmt.Println()

	db.View(func(tx database.Tx) error {
		fmt.Println("--------------------")
		tx.Data().Bucket(bucketName).ForEach(func(k, v []byte) error {

			fmt.Println("key : ", base64.StdEncoding.EncodeToString(k))
			//fmt.Println("key58 : ", base58.CheckEncode(k, 1))
			fmt.Println("value: ", base64.StdEncoding.EncodeToString(v))
			return nil
		})
		return nil
	})

	fmt.Println()
}
//PrintDB ...
func PrintDB(db database.DB, bucketName []byte) {
	fmt.Println("---------------------------------------")
	db.View(func(tx database.Tx) error {
		tx.Data().Bucket(bucketName).ForEach(func(k, v []byte) error {

			fmt.Println("key: ", k)
			fmt.Println("value: ", v)

			return nil
		})
		return nil
	})
	fmt.Println("---------------------------------------")
}

//DbPutMasterKey put in bucket,key:masterKey,value:masterNode
func DbPutMasterKey(dbTx database.Tx, masterKey, masterNode []byte) error {

	masterKeyBucket := dbTx.Data().Bucket(dbnamespace.MasterKeyBucket)

	err := masterKeyBucket.Put(masterKey, masterNode)
	if err != nil {
		log.Errorf("Failed to put mesterKey")
		return errors.WithMessage(err, "Failed to put mesterKey")
	}

	return nil
}

//DbFetchMasterKey fetch masterNode from bucket by masterKey
func DbFetchMasterKey(dbTx database.Tx, masterKey []byte) ([]byte, error) {

	masterKeyBucket := dbTx.Data().Bucket([]byte(dbnamespace.MasterKeyBucket))

	masterNode := masterKeyBucket.Get(masterKey)
	if masterNode == nil {
		log.Errorf("Account not found %v\n", masterKey)
		return nil, errors.New("Account not found")
	}

	return masterNode, nil
}

//DbPutCryptoKey put in bucket,key:[]byte("cryptoPub"),value:cryptoKey
func DbPutCryptoKey(dbTx database.Tx, cryptoKey []byte) error {

	cryptoKeyBucket := dbTx.Data().Bucket(dbnamespace.CryptoKeyBucket)

	err := cryptoKeyBucket.Put(dbnamespace.Crypto, cryptoKey)
	if err != nil {
		log.Errorf("Failed to put cryptoKey")
		return errors.WithMessage(err, "Failed to put cryptoKey")
	}

	return nil
}

//DbFetchCryptoKey fetch Crypto from bucket by cryptoKey
func DbFetchCryptoKey(dbTx database.Tx) ([]byte, error) {

	cryptoKeyBucket := dbTx.Data().Bucket([]byte(dbnamespace.CryptoKeyBucket))

	cryptoKey := cryptoKeyBucket.Get(dbnamespace.Crypto)
	if cryptoKey == nil {
		log.Errorf("CryptoKey not found %v\n", dbnamespace.Crypto)
		return nil, errors.New("CryptoKey not found")
	}

	return cryptoKey, nil
}

//DbPutCoinTypeKey put in bucket,key:coinTypeName,value:coinTypeKey
func DbPutCoinTypeKey(dbTx database.Tx, coinTypeName, coinTypeKey []byte) error {

	coinTypeKeyBucket := dbTx.Data().Bucket(dbnamespace.CoinTypeKeyBucket)

	err := coinTypeKeyBucket.Put(coinTypeName, coinTypeKey)
	if err != nil {
		log.Errorf("Failed to put CoinTypeKey")
		return errors.WithMessage(err, "Failed to put CoinTypeKey")
	}

	return nil
}

//DbFetchCoinTypeKey fetch coinTypeNode from bucket by coinTypeName
func DbFetchCoinTypeKey(dbTx database.Tx, coinTypeName []byte) ([]byte, error) {

	coinTypeKeyBucket := dbTx.Data().Bucket([]byte(dbnamespace.CoinTypeKeyBucket))

	coinTypeNode := coinTypeKeyBucket.Get(coinTypeName)
	if coinTypeNode == nil {
		log.Errorf("CoinTypeKey not found %v\n", coinTypeName)
		return nil, errors.New("CoinTypeKey not found")
	}

	return coinTypeNode, nil
}

//DbPutAccountInfo put in bucket,key:accountIndex,value:accountInfo
func DbPutAccountInfo(dbTx database.Tx, accountIndex uint32,
	accountInfo []byte) error {

	accountInfoBucket := dbTx.Data().Bucket(dbnamespace.AccountInfoBucket)

	accountIndexBytes := make([]byte, 8)
	binary.BigEndian.PutUint32(accountIndexBytes, accountIndex)
	err := accountInfoBucket.Put(accountIndexBytes, accountInfo)
	if err != nil {
		log.Errorf("Failed to put accountInfo")
		return errors.WithMessage(err, "Failed to put accountInfo")
	}

	return nil
}

//DbFetchAccountInfo fetch accountInfo from bucket by accountIndex
func DbFetchAccountInfo(dbTx database.Tx, accountIndex uint32) ([]byte, error) {

	accountInfoBucket := dbTx.Data().Bucket([]byte(dbnamespace.AccountInfoBucket))

	accountIndexBytes := make([]byte, 8)
	binary.BigEndian.PutUint32(accountIndexBytes, accountIndex)
	accountInfo := accountInfoBucket.Get(accountIndexBytes)
	if accountInfo == nil {
		log.Errorf("accountInfo not found %v\n", accountIndex)
		return nil, errors.New("accountInfo not found")
	}

	return accountInfo, nil
}

//DbPutAccountName put in bucket,key:accountIndex,value:accountName
func DbPutAccountName(dbTx database.Tx, accountIndex uint32,
	accountName []byte) error {

	accountNameBucket := dbTx.Data().Bucket(dbnamespace.AccountNameBucket)

	accountIndexBytes := make([]byte, 8)
	binary.BigEndian.PutUint32(accountIndexBytes, accountIndex)
	err := accountNameBucket.Put(accountIndexBytes, accountName)
	if err != nil {
		log.Errorf("Failed to put accountName")
		return errors.WithMessage(err, "Failed to put accountName")
	}

	return nil
}

//DbFetchAccountName fetch accountName from bucket by accountIndex
func DbFetchAccountName(dbTx database.Tx, accountIndex uint32) ([]byte, error) {

	accountNameBucket := dbTx.Data().Bucket([]byte(dbnamespace.AccountNameBucket))
	accountIndexBytes := make([]byte, 8)
	binary.BigEndian.PutUint32(accountIndexBytes, accountIndex)
	accountName := accountNameBucket.Get(accountIndexBytes)
	if accountName == nil {
		log.Errorf("accountName not found %v\n", accountIndex)
		return nil, errors.New("accountName not found")
	}

	return accountName, nil
}

//DbFetchAllAccounts get all accounts from AccountInfoBucket
func DbFetchAllAccounts(dbTx database.Tx) ([][]byte, error) {

	txaActBucket := dbTx.Data().Bucket(dbnamespace.AccountInfoBucket)
	accounts := make([][]byte, 0, 10)

	txaActBucket.ForEach(func(_, v []byte) error {
		accounts = append(accounts, v)
		return nil
	})

	return accounts, nil
}

//DbPutLastAccount put in bucket,key:[]byte("lastAccount"),value:index
func DbPutLastAccount(dbTx database.Tx, index uint32) error {

	lastAccountBucket := dbTx.Data().Bucket(dbnamespace.LastAccountBucket)

	lastAccountBytes := make([]byte, 8)
	binary.BigEndian.PutUint32(lastAccountBytes, index)

	return lastAccountBucket.Put(dbnamespace.LastAccount, lastAccountBytes)
}

//DbFetchLastAccount get last account
func DbFetchLastAccount(dbTx database.Tx) (uint32, error) {

	lastAccountBucket := dbTx.Data().Bucket([]byte(dbnamespace.
		LastAccountBucket))

	lastAccountBytes := lastAccountBucket.Get(dbnamespace.LastAccount)

	errString := "lastAccount not found"
	accountErr := e.NewWalletError(e.ErrNotFoundFormDB, errString, nil)
	if lastAccountBytes == nil {
		return math.MaxUint32, accountErr
	}

	lastAccount := uint32(binary.BigEndian.Uint32(lastAccountBytes))

	return lastAccount, nil
}

//DbPutLastUsedAccount put in bucket,key:[]byte("lastUsedAccount"),value:index
func DbPutLastUsedAccount(dbTx database.Tx, index uint32) error {

	lastUsedAccountBucket := dbTx.Data().Bucket(dbnamespace.LastUsedAccountBucket)

	lastUsedAccountBytes := make([]byte, 8)
	binary.BigEndian.PutUint32(lastUsedAccountBytes, index)

	return lastUsedAccountBucket.Put(dbnamespace.LastUsedAccount,
		lastUsedAccountBytes)
}

//DbFetchLastUsedAccount get last used account
func DbFetchLastUsedAccount(dbTx database.Tx) (uint32, error) {

	lastUsedAccountBucket := dbTx.Data().Bucket([]byte(dbnamespace.
		LastUsedAccountBucket))

	lastUsedAccountBytes := lastUsedAccountBucket.Get(dbnamespace.LastUsedAccount)
	if lastUsedAccountBytes == nil {
		return math.MaxUint32, fmt.Errorf("lastAccountBytes not found ")
	}

	lastUsedAccount := uint32(binary.BigEndian.Uint32(lastUsedAccountBytes))

	return lastUsedAccount, nil
}

//DbPutSecretKey put in bucket,key:[]byte("secretKey"),value:SecretKey
func DbPutSecretKey(dbTx database.Tx, value []byte) error {

	secretKeyBucket := dbTx.Data().Bucket(dbnamespace.SecretKeyBucket)

	return secretKeyBucket.Put(dbnamespace.SecretKey, value)
}

//DbFetchSecretKey get secretKeyBytes
func DbFetchSecretKey(dbTx database.Tx) ([]byte, error) {

	secretKeyBucket := dbTx.Data().Bucket(dbnamespace.SecretKeyBucket)

	secretKeyBytes := secretKeyBucket.Get(dbnamespace.SecretKey)

	errString := "secretKey not found"
	if secretKeyBytes == nil {
		return nil, e.NewWalletError(e.ErrNotFoundFormDB, errString, nil)
	}

	return secretKeyBytes, nil
}

//DbPutAssetName put in bucket,key:Asset,value:Name
func DbPutAssetName(dbTx database.Tx, key hash.HashType, value []byte) error {
	assetNameBucket := dbTx.Data().Bucket(dbnamespace.AssetNameBucket)

	err := assetNameBucket.Put(key, value)
	if err != nil {
		errString := fmt.Sprintf("Failed to put asset-name %v", key)
		return e.NewWalletError(e.ErrPutDB, errString, err)
	}
	return nil
}

//DbFetchAssetName get name by asset
func DbFetchAssetName(dbTx database.Tx, key hash.HashType) ([]byte, error) {
	assetNameBucket := dbTx.Data().Bucket([]byte(dbnamespace.AssetNameBucket))

	value := assetNameBucket.Get(key)
	if value == nil {
		errString := fmt.Sprintf("Failed to find asset-name %v", key)
		return nil, e.NewWalletError(e.ErrNotFoundFormDB, errString, nil)
	}

	return value, nil
}

//DbDeleteAssetName delete name by asset
func DbDeleteAssetName(dbTx database.Tx, key hash.HashType) error {
	assetNameBucket := dbTx.Data().Bucket([]byte(dbnamespace.AssetNameBucket))
	err := assetNameBucket.Delete(key)
	if err != nil {
		errString := fmt.Sprintf("Failed to delete asset-name %v", key)
		return e.NewWalletError(e.ErrDeleteDB, errString, err)
	}

	return nil
}

//DbHasAssetName  this data if or not exists in the bucket
func DbHasAssetName(dbTx database.Tx, key hash.HashType) bool {
	assetNameBucket := dbTx.Data().Bucket(dbnamespace.AssetNameBucket)
	return assetNameBucket.KeyExists(key)
}

//DbPutNameAsset put in bucket,key:name,value:asset
func DbPutNameAsset(dbTx database.Tx, key []byte, value hash.HashType) error {
	nameAssetBucket := dbTx.Data().Bucket(dbnamespace.NameAssetBucket)

	err := nameAssetBucket.Put(key, value)
	if err != nil {
		errString := fmt.Sprintf("Failed to put name-asset %v", key)
		return e.NewWalletError(e.ErrPutDB, errString, err)
	}
	return nil
}

//DbFetchNameAsset get asset by name
func DbFetchNameAsset(dbTx database.Tx, key []byte) ([]byte, error) {
	nameAssetBucket := dbTx.Data().Bucket([]byte(dbnamespace.NameAssetBucket))

	value := nameAssetBucket.Get(key)
	if value == nil {
		errString := fmt.Sprintf("Failed to find name-asset %v", key)
		return nil, e.NewWalletError(e.ErrNotFoundFormDB, errString, nil)
	}

	return value, nil
}

//DbDeleteNameAsset delete asset by name
func DbDeleteNameAsset(dbTx database.Tx, key []byte) error {
	nameAssetBucket := dbTx.Data().Bucket([]byte(dbnamespace.NameAssetBucket))
	err := nameAssetBucket.Delete(key)
	if err != nil {
		errString := fmt.Sprintf("Failed to delete name-asset %v", key)
		return e.NewWalletError(e.ErrDeleteDB, errString, err)
	}

	return nil
}

//DbHasNameAsset  this data if or not exists in the bucket
func DbHasNameAsset(dbTx database.Tx, key []byte) bool {
	nameAssetBucket := dbTx.Data().Bucket(dbnamespace.NameAssetBucket)
	return nameAssetBucket.KeyExists(key)
}

//GetAllAsset get all asset
func GetAllAsset(db database.DB) (map[string]string,error){
	var assets  map[string]string
	err:=db.View(func(tx database.Tx) error {
		tx.Data().Bucket(dbnamespace.NameAssetBucket).ForEach(func(k, v []byte) error {
			if len(k)!=0 {
				key:=string(k)
				assets[key] = base64.StdEncoding.EncodeToString(v)
			}

			return nil
		})
		return nil
	})
	if err!=nil{
		return nil,err
	}
	return assets,nil
}

