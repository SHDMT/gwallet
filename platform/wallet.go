package platform

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/SHDMT/btcec"
	"github.com/SHDMT/gravity/infrastructure/crypto/hash"
	"github.com/SHDMT/gravity/platform/consensus/genesis"
	"github.com/SHDMT/gwallet/infrastructure/config"
	"github.com/SHDMT/gwallet/infrastructure/database"
	e "github.com/SHDMT/gwallet/infrastructure/errors"
	"github.com/SHDMT/gwallet/infrastructure/log"
	"github.com/SHDMT/gwallet/infrastructure/utils"
	"github.com/SHDMT/gwallet/platform/addrmgr"
	"github.com/SHDMT/gwallet/platform/dag"
	"github.com/SHDMT/gwallet/platform/message"
	"github.com/SHDMT/gwallet/platform/unitassemble"
	"github.com/SHDMT/gwallet/platform/utxo"
	"github.com/SHDMT/gwallet/platform/walletdb"
	"github.com/SHDMT/gwallet/platform/walletseed"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"math/big"
	"os"
	"strings"
	"sync"
)

var (
	// DefaultAssetName the default asset name for gravity
	DefaultAssetName = "Gravity"

	// DefaultAccountName gravity default account name
	DefaultAccountName = "default"

	errGenerateAddressFailed = "generate default address failed"
)


// Wallet wallet manager
type Wallet struct {
	config       *config.Params
	db           database.DB
	Addrmgr      *addrmgr.AddressManager
	Utxomgr      *utxo.UnspentManager
	Messagemgr   *message.TXManager
	UnitAssemble *unitassemble.UnitAssemble
	DagClient    *dag.GravityClient
	wg           sync.WaitGroup
	CryptoKey    *addrmgr.CryptoKey
	quit         chan struct{}
	quitMu       sync.Mutex
}

// NewWallet create a new wallet instance to manage wallet
func NewWallet(config *config.Params, db database.DB, password []byte) (*Wallet, error) {
	dagClient := dag.NewClient(db)

	var cryptoKey = new(addrmgr.CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(db)
	if err != nil {
		return nil, err
	}

	secretKeyBytes, err := dbFetchSecretKey(db)
	if err != nil {
		log.Error(" can't load secretKey from database, please retry again")
		return nil, err
	}
	var secretKey addrmgr.SecretKey
	err = secretKey.Unmarshal(secretKeyBytes)
	if err != nil {
		log.Error(" test : create new secret key failed . ")
		return nil, err
	}
	err = secretKey.DeriveKey(&password)
	if err != nil {
		log.Error(" can't derive secret key : ", err)
		return nil, err
	}

	cryptoKeyDec, err := secretKey.Decrypt(cryptoKeyEnc)
	if err != nil {
		log.Error(" decrypt Cryptokey failed : ", err)
		return nil, err
	}
	copy(cryptoKey[:], cryptoKeyDec)

	keyStore := addrmgr.NewKeyStore(db, cryptoKey)
	addrMgr := addrmgr.NewAddressManager(keyStore, db)
	utxoMgr := utxo.NewUTXOManager(db)
	messageMgr, err := message.NewTXManager(db, utxoMgr, addrMgr)
	if err != nil {
		log.Error("can't create messageManager : ", err)
		return nil, err
	}

	unitAssemble := unitassemble.NewUnitAssemble(db, utxoMgr, addrMgr,
		messageMgr, dagClient, cryptoKey)

	return &Wallet{
		config:       config,
		db:           db,
		Addrmgr:      addrMgr,
		Utxomgr:      utxoMgr,
		Messagemgr:   messageMgr,
		UnitAssemble: unitAssemble,
		CryptoKey:    cryptoKey,
		DagClient:    dagClient,
	}, nil
}

// Start wallet service
func (w *Wallet) Start() {
	log.Info(" wallet starting ....")
	dagServer := dag.NewRPCServer(w.Messagemgr, w.DagClient)
	dagServer.Start()
	w.DagClient.Start()
	fmt.Print("=======result>>>>>>>")
	fmt.Print(true)
	fmt.Println("<<<<<<<result=======")
	var lastMci uint64
	var err error
	err = w.db.View(func(tx database.Tx) error {

		lastMci, err = walletdb.DbFetchLastMci(tx)

		return err
	})
	if err != nil {
		log.Error(" fetch lastMCI failed : ", err)
	}

	go w.syncToDag(lastMci)
}

// Stop wallet service
func (w *Wallet) Stop() {
	log.Info(" close wallet ")
	if w.db != nil {
		w.db.Close()
	}
}

// NewWalletTips The input prompt when create a new wallet
func NewWalletTips(dbFile string, pass string, seeds string) (string, error) {
	var password = []byte{}
	var seed []byte

	if pass == "" {
		var reader *bufio.Reader
		var err error

		exist, err := utils.FileExists(dbFile)
		if err != nil {
			return "", errors.New("can't check db file")
		}
		if exist {
			log.Info(" The wallet already exist. please run without --create option. ")
			return "", errors.New("wallet is already exist")
		}

		for {
			reader = bufio.NewReader(os.Stdin)
			password, err = InputPrompt(reader,
				"[ Please Enter wallet password ]", false)
			if err != nil {
				log.Error("[ Failed to enter password , please try again ]")
				continue
			}
			break
		}
	} else {
		password = []byte(pass)
	}

	if seeds == "" {
		reader := bufio.NewReader(os.Stdin)
		var err error
		log.Info(" will generate wallet seed ... ")
		useUserSeed, err := promptListBool(reader, "Do you have an "+
			"existing wallet seed you want to use?", "no")
		if err != nil {
			return "", err
		}
		if !useUserSeed {
			seed, _, err = walletseed.SeedGenerator()
			if err != nil {
				return "", err
			}
		} else {
			seed, err = walletseed.SeedRecover(reader)
			if err != nil {
				return "", err
			}
			if len(seed) < walletseed.MinSeedBytes || len(seed) > walletseed.MaxSeedBytes {
				return "", walletseed.ErrInvalidSeedLen
			}
		}

		log.Infof(" [your wallet seed is ] : %x \n", seed)
		for {
			fmt.Print(`Once you have stored the seed in a safe ` +
				`and secure location, enter "OK" to continue: `)
			confirmSeed, err := reader.ReadString('\n')
			if err != nil {
				return "", errors.New(" wallet create has abort")
			}
			confirmSeed = strings.TrimSpace(confirmSeed)
			confirmSeed = strings.Trim(confirmSeed, `"`)
			if strings.EqualFold("OK", confirmSeed) {
				break
			}
		}
	} else {
		var err error
		log.Info("[input seed :]  %s \n", seeds)
		seed, err = walletseed.SeedValidate(seeds)
		if err != nil {
			return "", err
		}
	}
	defaultAddress, err := CreateWallet(dbFile, password, seed)
	if err != nil {
		return "", err
	}
	return defaultAddress, nil
}

// CreateWallet create a new wallet use pass and wallet seeds
func CreateWallet(dbFile string, password []byte, seed []byte) (string, error) {
	// create wallet database
	db, err := CreateWalletDb(dbFile)
	if err != nil {
		log.Error(" can't create wallet database: ", err)
		return "", err
	}

	err = walletdb.RecordUpdateTime(db)
	if err != nil {
		log.Warn("Failed to record update timestamp: ", err)
	}
	log.Info(" wallet database create succeed !")

	// generate wallet master key
	masterNode, err := NewMaster(seed, *config.Parameters)
	if err != nil {
		return "", errors.New("derive master key failed")
	}

	// Derive the coinType key according to BIP0044.
	coinTypeKeyPriv, err := deriveCoinTypeKey(masterNode, config.Parameters.HDCoinType)
	if err != nil {
		return "", errors.New("failed to derive coinType extended key")
	}
	defer coinTypeKeyPriv.Zero()

	coinTypeKeyPub, err := coinTypeKeyPriv.PublicKey()
	if err != nil {
		log.Error(" can't derive public coinType key : ", err)
		return "", errors.New("failed to derive public coinType key")
	}

	// create default ecdsa account
	defaultAccountKeyPriv, err := coinTypeKeyPriv.DeriveAccountKey(addrmgr.DefaultAccountNum,
		addrmgr.SECP256K1)
	if err != nil {
		log.Error(" derive account key failed : ", err)
		return "", err
	}
	defer defaultAccountKeyPriv.Zero()

	defaultAccountKeyPub, err := defaultAccountKeyPriv.PublicKey()
	if err != nil {
		log.Error(" derive account pulickey failed :", err)
		return "", err
	}
	secretKey, err := addrmgr.NewSecretKey(&password, addrmgr.DefaultN,
		addrmgr.DefaultR, addrmgr.DefaultP)
	if err != nil {
		log.Error(" generate secret key failed : ", err)
		return "", err
	}

	secretKeyBytes := secretKey.Marshal()
	saveSecretKey(db, secretKeyBytes)

	cryptoKey, err := addrmgr.GenerateCryptoKey()
	if err != nil {
		log.Error(" generate cryptoKey failed : ", err)
		return "", err
	}
	masterPriv, err := masterNode.Marshal()
	if err != nil {
		log.Error("marshal private masterKey to database failed ", err)
		return "", err
	}
	masterPrivEnc, err := cryptoKey.Encrypt(masterPriv)
	if err != nil {
		log.Error("encrypt private masterKey failed , ", err)
		return "", err
	}
	saveMasterKey(db, []byte("masterPriv"), masterPrivEnc)
	masterPubKey, err := masterNode.PublicKey()
	if err != nil {
		log.Error(" derive public masterKey failed , ", err)
		return "", err
	}
	masterPub, err := masterPubKey.Marshal()
	if err != nil {
		log.Error("save private masterkey to database failed , ", err)
		return "", err
	}
	masterPubEnc, err := cryptoKey.Encrypt(masterPub)
	if err != nil {
		log.Error("encrypt public masterKey failed : ", err)
		return "", err
	}
	saveMasterKey(db, []byte("masterPub"), masterPubEnc)

	cryptoKeyEnc, err := secretKey.Encrypt(cryptoKey.Bytes())
	err = saveCryptoKey(db, cryptoKeyEnc)
	if err != nil {
		log.Error(" put cryptoKey to database failed , ", err)
		return "", err
	}

	coinTypeKeyPrivBytes, err := coinTypeKeyPriv.Marshal()
	if err != nil {
		log.Error(" extended PrivateKey marshal failed : ", err)
		return "", err
	}
	coinTypeKeyPrivEnc, err := cryptoKey.Encrypt(coinTypeKeyPrivBytes)
	if err != nil {
		log.Error(" encrypt coinTypeKeyPriv failed : ", err)
		return "", err
	}

	coinTypeKeyPubBytes, err := coinTypeKeyPub.Marshal()
	if err != nil {
		log.Error(" extended PublicKey marshal failed : ", err)
		return "", err
	}
	coinTypeKeyPubEnc, err := cryptoKey.Encrypt(coinTypeKeyPubBytes)
	if err != nil {
		log.Error(" encrypt coinTypeKeyPub failed : ", err)
		return "", err
	}
	err = saveCoinTypeKey(db, []byte("coinPriv"), coinTypeKeyPrivEnc)
	if err != nil {
		log.Error(" put private coinTypeKey to database failed , ", err)
		return "", err
	}
	err = saveCoinTypeKey(db, []byte("coinPub"), coinTypeKeyPubEnc)
	if err != nil {
		log.Error(" put public coinTypeKey to database failed , ", err)
		return "", err
	}
	defaultAcctPrivKeyBytes, err := defaultAccountKeyPriv.Marshal()
	if err != nil {
		log.Error(" extended PrivateKey marshal failed : ", err)
		return "", err
	}
	defaultAcctPrivKeyEnc, err := cryptoKey.Encrypt(defaultAcctPrivKeyBytes)
	if err != nil {
		log.Error(" extended Key crypto failed ")
		return "", err
	}
	defaultAcctPubKeyBytes, err := defaultAccountKeyPub.Marshal()
	if err != nil {
		log.Error(" extended PublicKey marshal failed : ", err)
		return "", err
	}
	defaultAcctPubKeyEnc, err := cryptoKey.Encrypt(defaultAcctPubKeyBytes)
	assetList := make([]hash.HashType, 0)
	assetList = append(assetList, genesis.GenesisAsset)
	defaultAccount := &addrmgr.AccountInfo{
		PrivKeyEnc: defaultAcctPrivKeyEnc,
		PubKeyEnc:  defaultAcctPubKeyEnc,

		ExternalIndex:         1,
		InternalIndex:         0,
		LastUsedExternalIndex: 0,
		LastUsedInternalIndex: 0,

		AccountName:  DefaultAccountName,
		AccountIndex: addrmgr.DefaultAccountNum,
		AccountType:  addrmgr.SECP256K1,
		AssetList:    assetList,
	}

	defaultAcctBytes, err := defaultAccount.EncodeAccountInfo()
	if err != nil {
		log.Error(" marshal account info to database failed , ", err)
		return "", err
	}
	err = saveAccountInfo(db, addrmgr.DefaultAccountNum, defaultAcctBytes)
	if err != nil {
		log.Error("  put account info to database failed , ", err)
		return "", err
	}
	saveAccountName(db, addrmgr.DefaultAccountNum, DefaultAccountName)
	saveDefaultAsset(db, DefaultAssetName, genesis.GenesisAsset)
	externalKey, err := defaultAccountKeyPriv.DeriveChildKey(0,
		addrmgr.SECP256K1)
	if err != nil {
		log.Warn(errGenerateAddressFailed)
		return "", nil
	}
	addrPrivKey, err := externalKey.DeriveChildKey(0, addrmgr.SECP256K1)
	if err != nil {
		log.Warn(errGenerateAddressFailed)
		return "", nil
	}
	log.Debugf("[default address privateKey is :] %x \n", addrPrivKey.Key)
	addrPubKey, err := addrPrivKey.PublicKey()
	if err != nil {
		log.Warn(errGenerateAddressFailed)
		return "", nil
	}
	log.Info("[default address publicKey is : ] %x \n", addrPubKey.Key)
	address, err := addrmgr.GetAddressByPubKey(db, addrmgr.DefaultAccountNum, false, false,
		uint32(0), addrPubKey)
	if err != nil {
		log.Warn(errGenerateAddressFailed)
		return "", nil
	}
	base64Address := base64.StdEncoding.EncodeToString(address.Address)
	log.Infof(" [default address is : ] %s \n", base64Address)

	importAccount := &addrmgr.AccountInfo{
		PrivKeyEnc: nil,
		PubKeyEnc:  nil,

		ExternalIndex:         0,
		InternalIndex:         0,
		LastUsedExternalIndex: 0,
		LastUsedInternalIndex: 0,

		AccountName:  "imported",
		AccountIndex: addrmgr.ImportedAccountNum,
		AccountType:  addrmgr.IMPORTED,
		AssetList:    assetList,
	}

	importAccountBytes, err := importAccount.EncodeAccountInfo()
	if err != nil {
		log.Error(" marshal account info to database failed , ", err)
		return base64Address, err
	}
	err = saveAccountInfo(db, addrmgr.ImportedAccountNum, importAccountBytes)
	if err != nil {
		log.Error("  put account info to database failed , ", err)
		return base64Address, err
	}
	saveAccountName(db, addrmgr.ImportedAccountNum, "imported")
	saveLastAccount(db, 1)
	saveLastUsedAccount(db, 0)
	log.Info(" wallet create success ")
	return base64Address, nil
}

// OpenWallet open a exists wallet
func OpenWallet(dbFile string, password []byte) (*Wallet, error) {
	db, err := OpenWalletDb(dbFile)
	if err != nil {
		log.Error(" create wallet database failed : ", err)
		return nil, err
	}
	err = walletdb.RecordUpdateTime(db)
	if err != nil {
		log.Warn("Failed to record update timestamp\n")
	}
	wallet, err := NewWallet(config.Parameters, db, password)
	if err != nil {
		log.Error(" open wallet failed: ", err)
		return nil, err
	}
	log.Info(" wallet opened . ")
	return wallet, nil
}

// OpenWalletDb open wallet database and return db instance
func OpenWalletDb(dbFile string) (database.DB, error) {
	exist, err := utils.FileExists(dbFile)
	if err != nil {
		log.Error(" check wallet exist failed : ", err)
		return nil, err
	}
	if !exist {
		log.Error(" The wallet not exist. ")
		return nil, err
	}
	db, err := database.Open("badgerDB", dbFile, dbFile)
	if err != nil {
		return nil, err
	}

	return db, nil
}

// CreateWalletDb create wallet database when you first create wallet
func CreateWalletDb(dbFile string) (database.DB, error) {
	exist, err := utils.FileExists(dbFile)
	if err != nil {
		log.Error(" check wallet exist failed : ", err)
		return nil, err
	}
	if exist {
		return nil, errors.New(" the wallet already exist. ")
	}

	db, err := database.Create("badgerDB", dbFile, dbFile)
	if err != nil {
		return nil, err
	}
	log.Info("create database bucket ")
	err = walletdb.CreateWalletBucket(db)
	if err != nil {
		log.Error(" create bucket failed : ", err)
		return nil, err
	}

	return db, nil
}

func (w *Wallet) syncToDag(startMci uint64) {
	log.Info(" will sync to gravity ...")
	var err error

	var addresses [][]byte
	err = w.db.View(func(tx database.Tx) error {
		addresses, err = walletdb.DbListAllMyAddress(tx)
		if err != nil {
			log.Error(" list all my address failed : ", err)
			return err
		}
		return nil
	})
	if err != nil {
		log.Error(" list all address failed : ", err)
	}
	addressList := make([]addrmgr.Address, 0)
	for _, addr := range addresses {
		address, err := addrmgr.DecodeAddress(addr)
		if err != nil {
			log.Error(" decode address failed : ", err)
			continue
		}
		addressList = append(addressList, *address)
	}

	log.Info(" will sync to gravity , lastMCi :  ", startMci, " address count : ", len(addressList))
	w.DagClient.InitAddress(addressList, startMci)
}

// InputPrompt The input prompt when you create or recover a new wallet
func InputPrompt(reader *bufio.Reader, prefix string, confirm bool) ([]byte,
	error) {

	// Prompt the user until they enter a passphrase.
	prompt := fmt.Sprintf("%s: ", prefix)
	for {
		fmt.Print(prompt)
		var pass []byte
		var err error
		fd := int(os.Stdin.Fd())
		if terminal.IsTerminal(fd) {
			pass, err = terminal.ReadPassword(fd)
		} else {
			pass, err = reader.ReadBytes('\n')
			if err == io.EOF {
				err = nil
			}
		}
		if err != nil {
			return nil, err
		}
		fmt.Print("\n")
		pass = bytes.TrimSpace(pass)
		if len(pass) == 0 {
			continue
		}

		if !confirm {
			return pass, nil
		}

		fmt.Print("Confirm passphrase: ")
		confirm, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
		fmt.Print("\n")
		confirm = bytes.TrimSpace(confirm)
		if !bytes.Equal(pass, confirm) {
			fmt.Println("The entered passphrases do not match")
			continue
		}

		return pass, nil
	}
}

// NewMaster create the masterKey from the specified seed and config
func NewMaster(seed []byte, net config.Params) (*addrmgr.ExtendedKey, error) {
	// Per [BIP32], the seed must be in range [MinSeedBytes, MaxSeedBytes].
	if len(seed) < walletseed.MinSeedBytes || len(seed) > walletseed.MaxSeedBytes {
		return nil, walletseed.ErrInvalidSeedLen
	}

	//   I = HMAC-SHA512(Key = "Gravity seed", Data = Seed)
	hmac512 := hmac.New(sha512.New, []byte(walletseed.ChainMaster))
	hmac512.Write(seed)
	l := hmac512.Sum(nil)

	// Split "I" into two 32-byte sequences Il and Ir where:
	//   Il = master secret key
	//   Ir = master chain code
	secretKey := l[:len(l)/2]
	chainCode := l[len(l)/2:]

	// Ensure the key in usable.
	secretKeyNum := new(big.Int).SetBytes(secretKey)
	if secretKeyNum.Cmp(btcec.S256().N) >= 0 || secretKeyNum.Sign() == 0 {
		return nil, walletseed.ErrUnusableSeed
	}

	parentFP := []byte{0x00, 0x00, 0x00, 0x00}

	return &addrmgr.ExtendedKey{
		Version:     net.HDPrivateKeyID[:],
		Depth:       0,
		ParentFP:    parentFP,
		ChainCode:   chainCode,
		ChildNumber: 0,
		Key:         secretKey,
		IsPrivate:   true,
		AlgType:     0,
	}, nil
}

func deriveCoinTypeKey(masterNode *addrmgr.ExtendedKey, coinType uint32) (*addrmgr.ExtendedKey, error) {
	// Enforce maximum coin type.
	if coinType > addrmgr.MaxCoinType {
		return nil, addrmgr.ErrInvalidCoinType
	}

	purpose, err := masterNode.Child(44+addrmgr.HardenedKeyStart, true, addrmgr.SECP256K1)
	if err != nil {
		return nil, err
	}

	// Derive the coin type key as a child of the purpose key.
	coinTypeKey, err := purpose.Child(coinType+addrmgr.HardenedKeyStart, true, addrmgr.SECP256K1)
	if err != nil {
		return nil, err
	}

	return coinTypeKey, nil
}

// Lock locked the wallet , User cannot access encrypted data
func (w *Wallet) Lock() {
	w.CryptoKey.Zero()
}

// Unlock unlock the locked wallet
func (w *Wallet) Unlock(pass string) error {

	cryptoKey, err := w.getCryptoKey(pass)
	if err != nil {
		log.Errorf(" can't unlock wallet : %s \n", err.Error())
		return fmt.Errorf(" can't unlock wallet : %s ", err.Error())
	}
	w.CryptoKey = cryptoKey
	return nil
}

// Locked check the wallet is locked or not
func (w *Wallet) Locked() bool {
	zeroBytes := make([]byte, 32)
	if w.CryptoKey == nil || bytes.Equal(zeroBytes, w.CryptoKey.Bytes()) {
		return true
	}
	return false
}

// DumpPrivateKey dump the private key of the specified wallet address
func (w *Wallet) DumpPrivateKey(addressString string) (string, error) {

	address, err := base64.StdEncoding.DecodeString(addressString)
	errString := "Base64 decodeString failed！"
	if err != nil {
		return "", e.NewWalletError(e.ErrDumpPrivKey, errString, err)
	}

	key, err := w.dumpWIFPrivateKey(address)
	errString = "DumpWIFPrivateKey address failed！"
	if err != nil {
		if w.Locked() {
			errString = "Wallet is locked！"
			return "", e.NewWalletError(e.ErrLocked, errString, err)
		}
		return "", e.NewWalletError(e.ErrDumpPrivKey, errString, err)
	}
	return key, nil
}

func (w *Wallet) dumpWIFPrivateKey(addr []byte) (string, error) {

	if w.Locked() {
		log.Warnf(" wallet is lock , you must unlock it first ")
		return "", errors.New(" wallet is locked")
	}

	address, err := addrmgr.DBFetchAddress(w.db, addr)
	if err != nil {
		log.Info(" can't find the specified address. ")
		return "", err
	}

	accountInfoBytes, err := dbFetchAccountInfo(w.db, address.Account)
	var acctInfo addrmgr.AccountInfo
	err = acctInfo.DecodeAccountInfo(accountInfoBytes)
	if err != nil {
		log.Error(" accountInfo unmarshal failed: ", err)
		return "", err
	}
	var privkey []byte
	if acctInfo.AccountType == addrmgr.BLISS {
		privExtendedKey, err := dbFetchPrivateKey(w.db, address.PubKey)
		if err != nil {
			return "", err
		}
		privkey = privExtendedKey.Key
	} else {
		acctPrivKeyBytes, err := w.CryptoKey.Decrypt(acctInfo.PrivKeyEnc)
		if err != nil {
			return "", errors.New(" can't decrypt account privatekey ")
		}
		acctPrivKey := new(addrmgr.ExtendedKey)
		err = acctPrivKey.UnMarshal(acctPrivKeyBytes)
		if err != nil {
			return "", errors.New(" can't unmarshal account privatekey ")
		}
		branch := uint32(0)
		if address.Internal {
			branch = 1
		}
		privExtendedKey, err := acctPrivKey.DerivPrivKey(branch,
			address.Index, addrmgr.SECP256K1)
		if err != nil {
			return "", err
		}
		privkey = privExtendedKey.Key
	}

	wifKey, err := addrmgr.NewWIF(privkey, config.Parameters, addrmgr.BLISS)
	if err != nil {
		return "", nil
	}
	return wifKey.String(), nil
}

// ImportPrivKey import private key , and you can spend the asset which locked by this private key
func (w *Wallet) ImportPrivKey(privateKey string) (string, error) {
	var address string

	addr, err := w.Addrmgr.GetImportedAddress(privateKey)
	if err != nil {
		log.Error(" import privateKey failed: ", err)
		return "", err
	}
	if w.DagClient != nil {
		w.DagClient.UpdateAddress(*addr)
	}

	address = base64.StdEncoding.EncodeToString(addr.Address)
	return address, nil
}

// UpdatePassword update wallet password with new password, You must verify with the old password.
func (w *Wallet) UpdatePassword(oldPass string, newPass string) error {
	cryptoKey, err := w.getCryptoKey(oldPass)
	if err != nil {
		log.Error(" can't derive crypto key,: ", err)
		return err
	}

	password := []byte(newPass)
	secretKey, err := addrmgr.NewSecretKey(&password, addrmgr.DefaultN,
		addrmgr.DefaultR, addrmgr.DefaultP)
	if err != nil {
		log.Error(" generate secret key failed : ", err)
		return err
	}
	secretKeyBytes := secretKey.Marshal()
	saveSecretKey(w.db, secretKeyBytes)

	cryptoKeyEnc, err := secretKey.Encrypt(cryptoKey.Bytes())
	err = saveCryptoKey(w.db, cryptoKeyEnc)
	if err != nil {
		log.Error(" put cryptoKey to database failed , ", err)
		return err
	}

	return nil
}

func (w *Wallet) discoverActiveAddress(fromMCI uint64) error {
	coinTypeKeyEnc, err := dbFetchCoinTypeKey(w.db)
	if err != nil {
		log.Error("can't fetch coinType key from database")
		return err
	}
	coinTypeKeyDec, err := w.CryptoKey.Decrypt(coinTypeKeyEnc)
	if err != nil {
		log.Error(" can't decrypt coinTypeKey: %s", err)
		return fmt.Errorf("can't decrypto cointypekey: %s", err)
	}

	coinTypeKey := new(addrmgr.ExtendedKey)
	err = coinTypeKey.UnMarshal(coinTypeKeyDec)
	if err != nil {
		log.Error(" can't unmarshal coinType: ", err)
		return fmt.Errorf(" can't unmarshal cointype: %s", err.Error())
	}
	w.disCoverActiveAddresses(coinTypeKey, fromMCI)
	return nil
}

type accountInfo struct {
	used        bool
	acctIndex   uint32
	lastAddress uint32
	acctType    int
}

func (w *Wallet) disCoverActiveAddresses(coinTypeKey *addrmgr.ExtendedKey, fromMCI uint64) error {
	accts, err := w.findLastUsedAccount(coinTypeKey, fromMCI)
	if err != nil {
		log.Error("can't find last used account")
		return err
	}

	for _, acct := range accts {
		lastExternalAddr := uint32(0)
		lastInternalAddr := uint32(0)
		acctPrivKey, err := coinTypeKey.DeriveAccountKey(acct.acctIndex, acct.acctType)
		if err != nil {
			log.Error(" can't derive account key")
			return err
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			used, lastAddr, _ := w.findLastUsedAddress(acctPrivKey, acct.acctIndex, addrmgr.ExternalBranch, acct.acctType, fromMCI)
			if used {
				lastExternalAddr = lastAddr
				err = w.Addrmgr.RecoverAllUsedAddress(acctPrivKey, acct.acctIndex, addrmgr.ExternalBranch, acct.acctType, lastExternalAddr)
			}
			wg.Done()
		}()

		go func() {
			used, lastAddr, _ := w.findLastUsedAddress(acctPrivKey, acct.acctIndex, addrmgr.InternalBranch, acct.acctType, fromMCI)
			if used {
				lastInternalAddr = lastAddr
				err = w.Addrmgr.RecoverAllUsedAddress(acctPrivKey, acct.acctIndex, addrmgr.InternalBranch, acct.acctType, lastInternalAddr)
			}
			wg.Done()
		}()

		wg.Wait()

		acctPrivBytes, _ := acctPrivKey.Marshal()
		acctPrivEnc, _ := w.CryptoKey.Encrypt(acctPrivBytes)

		acctPubKey, _ := acctPrivKey.PublicKey()
		acctPubKeyBytes, _ := acctPubKey.Marshal()
		acctPubKeyEnc, _ := w.CryptoKey.Encrypt(acctPubKeyBytes)

		acctName := fmt.Sprintf("Account-%d", acct.acctIndex)
		if acct.acctIndex == addrmgr.DefaultAccountNum {
			acctName = DefaultAccountName
		}
		assetList := make([]hash.HashType, 0)
		assetList = append(assetList, genesis.GenesisAsset)
		acctInfo := &addrmgr.AccountInfo{
			PrivKeyEnc: acctPrivEnc,
			PubKeyEnc:  acctPubKeyEnc,

			ExternalIndex:         lastExternalAddr,
			InternalIndex:         lastInternalAddr,
			LastUsedExternalIndex: lastExternalAddr,
			LastUsedInternalIndex: lastInternalAddr,

			AccountName:  acctName,
			AccountIndex: acct.acctIndex,
			AccountType:  acct.acctType,
			AssetList:    assetList,
		}
		acctBytes, _ := acctInfo.EncodeAccountInfo()
		errList := make([]error, 4)
		err = w.db.Update(func(tx database.Tx) error {
			errList[0] = walletdb.DbPutLastAccount(tx, acct.acctIndex)
			errList[1] = walletdb.DbPutAccountInfo(tx, acct.acctIndex, acctBytes)
			errList[2] = walletdb.DbPutAccountName(tx, acct.acctIndex, []byte(acctName))
			errList[3] = walletdb.DbPutAccount(tx, []byte(acctName), acct.acctIndex)

			for _, err := range errList {
				errString := "Put DB failed!"
				if err != nil {
					return e.NewWalletError(e.ErrPutDB, errString, err)
				}
			}
			return nil
		})
		if err != nil {
			log.Warn(" can't put account info to database.")
		}
	}

	return nil
}

func (w *Wallet) findLastUsedAccount(coinTypeKey *addrmgr.ExtendedKey, fromMCI uint64) ([]accountInfo, error) {
	lastAccount := uint32(0)
	var err error
	lastAccount, err = dbFetchLastAccount(w.db)
	if err != nil {
		log.Error(" can't fetch last account from database")
	}
	requestAccount := make([]accountInfo, 0)
	var (
		lastUsed uint32
		lo, hi    = lastAccount, uint32(addrmgr.HardenedKeyStart) / addrmgr.ScanLength
	)

Bsearch:
	for lo <= hi {
		mid := (hi + lo) / 2
		var r accountInfo
		var wgs sync.WaitGroup
		account := mid
		wgs.Add(2)
		go func() {
			used, _ := w.checkAcctUsed(coinTypeKey, account, addrmgr.SECP256K1, fromMCI)
			if used {
				r = accountInfo{used: used, acctIndex: account, acctType: addrmgr.SECP256K1}
			}
			wgs.Done()
		}()
		go func() {
			used, _ := w.checkAcctUsed(coinTypeKey, account, addrmgr.BLISS, fromMCI)
			if used {
				r = accountInfo{used: used, acctIndex: account, acctType: addrmgr.BLISS}
			}
			wgs.Done()
		}()
		wgs.Wait()

		if r.used {
			lastUsed = r.acctIndex
			lo = mid + 1
			continue Bsearch
		}
		if mid == lastUsed {
			break
		}
		hi = mid - 1
	}

	for i := uint32(1); i <= lastUsed; i++ {
		var wg sync.WaitGroup
		wg.Add(2)

		account := i
		var acctResult accountInfo
		go func() {
			used, _ := w.checkAcctUsed(coinTypeKey, account, addrmgr.SECP256K1, fromMCI)
			if used {
				acctResult = accountInfo{used: used, acctType: addrmgr.SECP256K1, acctIndex: account}
			}
			wg.Done()
		}()

		go func() {
			used, _ := w.checkAcctUsed(coinTypeKey, account, addrmgr.BLISS, fromMCI)
			if used {
				acctResult = accountInfo{used: used, acctType: addrmgr.BLISS, acctIndex: account}
			}
			wg.Done()
		}()
		wg.Wait()

		requestAccount = append(requestAccount, acctResult)
	}
	return requestAccount, nil
}

func (w *Wallet) checkAcctUsed(coinTypeKey *addrmgr.ExtendedKey, acct uint32, acctType int, fromMCI uint64) (bool, error) {
	acctPrivKey, err := coinTypeKey.DeriveAccountKey(acct, acctType)
	if err != nil {
		log.Error(" can't derive account key")
		return false, err
	}

	var wg sync.WaitGroup

	var acctUsed bool
	wg.Add(2)
	go func() {
		used, _, _ := w.findLastUsedAddress(acctPrivKey, acct, addrmgr.ExternalBranch, acctType, fromMCI)
		if used {
			acctUsed = true
		}
		wg.Done()
	}()
	go func() {
		used, _, _ := w.findLastUsedAddress(acctPrivKey, acct, addrmgr.InternalBranch, acctType, fromMCI)
		if used {
			acctUsed = true
		}
		wg.Done()
	}()
	wg.Wait()

	if acctUsed {
		return true, nil
	}
	return false, nil
}

func (w *Wallet) findLastUsedAddress(acctPrivKey *addrmgr.ExtendedKey, acct uint32, branch uint32, acctType int, fromMCI uint64) (bool, uint32, error) {
	var (
		lastUsed        = ^uint32(0)
		scanLen         = uint32(addrmgr.ScanLength)
		segments        = uint32(addrmgr.HardenedKeyStart) / scanLen
		lo, hi   uint32 = 0, segments - 1
	)
	var err error
	var AddrUsed bool
Bsearch:
	for lo <= hi {
		mid := (hi + lo) / 2
		var addrPrivs []*addrmgr.ExtendedKey
		addrPrivs, err = acctPrivKey.DerivPrivKeys(branch, mid*scanLen, mid*scanLen+20, acctType)
		if err != nil {
			return false, 0, err
		}
		addrs := make([]*addrmgr.Address, len(addrPrivs))
		for i, addrPriv := range addrPrivs {
			pubKey, err := addrPriv.PublicKey()
			if err != nil {
				log.Warn("can't get publicKey ")
				continue
			}
			addrHash := hash.Sum256(pubKey.Key)
			var addr *addrmgr.Address
			if branch == addrmgr.ExternalBranch {
				addr = addrmgr.NewAddress(acct, addrHash, false, false, mid*scanLen,
					pubKey.PublicKeyBytes())
			} else {
				addr = addrmgr.NewAddress(acct, addrHash, true, false, mid*scanLen,
					pubKey.PublicKeyBytes())
			}
			addrs[i] = addr
		}
		used, index, err := w.DagClient.FindAddress(addrs, fromMCI)
		if err != nil {
			log.Warn(" can't check address in DAG")
			continue
		}

		if used {
			AddrUsed = true
			lastUsed = mid*scanLen + index
			lo = mid + 1
			continue Bsearch
		}

		if mid == 0 {
			break
		}
		hi = mid - 1
	}
	return AddrUsed, lastUsed, nil
}

// Rescan rescan DAG from 'start' mci.
func (w *Wallet) Rescan(start uint64) {
	w.wg.Add(1)

	err := w.db.Update(func(tx database.Tx) error {
		err := walletdb.DbPutLastMci(tx, start)
		return err
	})
	if err != nil {
		log.Error(" can't reset lastMci to database")
		return
	}

	go func() {
		err := w.discoverActiveAddress(0)
		if err != nil {
			log.Error(" can't discover active address")
			return
		}
		w.wg.Done()
	}()
	w.wg.Wait()
	w.Messagemgr.LoadAccounts()
	w.Utxomgr.LoadAllUTXOsFromDb()
	go func() {
		w.syncToDag(start)
	}()
}

func (w *Wallet) getCryptoKey(pass string) (*addrmgr.CryptoKey, error) {
	password := []byte(pass)
	var cryptoKey = new(addrmgr.CryptoKey)
	cryptoKeyEnc, err := dbFetchCryptoKey(w.db)
	if err != nil {
		return nil, err
	}

	secretKeyBytes, err := dbFetchSecretKey(w.db)
	if err != nil {
		log.Error(" can't load secretKey from database, please retry again")
		return nil, err
	}

	var secretkey addrmgr.SecretKey
	err = secretkey.Unmarshal(secretKeyBytes)
	if err != nil {
		log.Error(" test : create new secret key failed . ")
		return nil, err
	}
	err = secretkey.DeriveKey(&password)
	if err != nil {
		log.Error(" can't derive secret key : ", err)
		return nil, err
	}

	cryptoKeyDec, err := secretkey.Decrypt(cryptoKeyEnc)
	if err != nil {
		log.Error(" decrypt Cryptokey failed : ", err)
		return nil, err
	}
	log.Debugf("cryptoKeyDec >>: %x \n", cryptoKeyDec)
	copy(cryptoKey[:], cryptoKeyDec)

	return cryptoKey, nil
}

func promptListBool(reader *bufio.Reader, prefix string, defaultEntry string) (bool, error) {
	// Setup the valid responses.
	valid := []string{"n", "no", "y", "yes"}
	response, err := promptList(reader, prefix, valid, defaultEntry)
	if err != nil {
		return false, err
	}
	return response == "yes" || response == "y", nil
}

func promptList(reader *bufio.Reader, prefix string, validResponses []string, defaultEntry string) (string, error) {
	// Setup the prompt according to the parameters.
	validStrings := strings.Join(validResponses, "/")
	var prompt string
	if defaultEntry != "" {
		prompt = fmt.Sprintf("%s (%s) [%s]: ", prefix, validStrings,
			defaultEntry)
	} else {
		prompt = fmt.Sprintf("%s (%s): ", prefix, validStrings)
	}

	// Prompt the user until one of the valid responses is given.
	for {
		fmt.Print(prompt)
		reply, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		reply = strings.TrimSpace(strings.ToLower(reply))
		if reply == "" {
			reply = defaultEntry
		}

		for _, validResponse := range validResponses {
			if reply == validResponse {
				return reply, nil
			}
		}
	}
}

func dbFetchCoinTypeKey(db database.DB) ([]byte, error) {

	var keyBytes []byte
	err := db.View(func(tx database.Tx) error {
		var err error
		keyBytes, err = walletdb.DbFetchCoinTypeKey(tx, []byte("coinPriv"))
		return err
	})
	return keyBytes, err
}

func dbFetchCryptoKey(db database.DB) ([]byte, error) {

	var cryptokey []byte
	err := db.View(func(tx database.Tx) error {
		var err error
		cryptokey, err = walletdb.DbFetchCryptoKey(tx)

		return err
	})
	if err != nil {
		return nil, err
	}
	return cryptokey, nil
}

func saveSecretKey(db database.DB, key []byte) error {

	err := db.Update(func(tx database.Tx) error {
		err := walletdb.DbPutSecretKey(tx, key)
		return err
	})

	return err
}

func dbFetchSecretKey(db database.DB) ([]byte, error) {
	var secretKey []byte
	err := db.View(func(tx database.Tx) error {
		var err error
		secretKey, err = walletdb.DbFetchSecretKey(tx)
		return err
	})

	if err != nil {
		return nil, err
	}
	return secretKey, nil
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

// saveLastUsedAccount put last used account index to database
func saveLastUsedAccount(db database.DB, value uint32) error {

	err := db.Update(func(tx database.Tx) error {
		err := walletdb.DbPutLastUsedAccount(tx, value)
		return err
	})

	return err
}

// saveAccountName put account index and account name to database
func saveAccountName(db database.DB, accountIndex uint32,
	accountName string) error {

	err := db.Update(func(tx database.Tx) error {

		err := walletdb.DbPutAccount(tx, []byte(accountName), accountIndex)
		if err != nil {
			return err
		}

		err = walletdb.DbPutAccountName(tx, accountIndex, []byte(accountName))
		if err != nil {
			return err
		}
		return nil
	})

	return err
}

// saveDefaultAsset put gravity default asset name and assetID to database
func saveDefaultAsset(db database.DB, name string, asset []byte) error {

	err := db.Update(func(tx database.Tx) error {
		err := walletdb.DbPutAssetName(tx, hash.HashType(asset), []byte(name))
		if err != nil {
			return err
		}
		err = walletdb.DbPutNameAsset(tx, []byte(name), hash.HashType(asset))
		return err
	})
	return err
}

// saveMasterKey put encrypted masterKey to database
func saveMasterKey(db database.DB, key, value []byte) error {

	err := db.Update(func(tx database.Tx) error {
		err := walletdb.DbPutMasterKey(tx, key, value)
		return err
	})

	return err
}

// saveCryptoKey put encrypted cryptoKey to database
func saveCryptoKey(db database.DB, value []byte) error {

	err := db.Update(func(tx database.Tx) error {
		err := walletdb.DbPutCryptoKey(tx, value)
		return err
	})
	return err
}

// saveCoinTypeKey put encrypted coinTypeKey to database
func saveCoinTypeKey(db database.DB, key, value []byte) error {

	err := db.Update(func(tx database.Tx) error {
		err := walletdb.DbPutCoinTypeKey(tx, key, value)
		return err
	})
	return err
}

// saveAccountInfo put account information to database
func saveAccountInfo(db database.DB, index uint32, value []byte) error {
	err := db.Update(func(tx database.Tx) error {
		err := walletdb.DbPutAccountInfo(tx, index, value)
		return err
	})
	return err
}

// saveLastAccount fetch account information of the specified account index
func dbFetchAccountInfo(db database.DB, account uint32) ([]byte, error) {
	var acctBytes []byte
	err := db.View(func(tx database.Tx) error {
		var err error
		acctBytes, err = walletdb.DbFetchAccountInfo(tx, account)

		return err
	})
	if err != nil {
		return nil, err
	}
	return acctBytes, nil
}

// saveLastAccount put last account index of the wallet
func saveLastAccount(db database.DB, value uint32) error {

	err := db.Update(func(tx database.Tx) error {
		err := walletdb.DbPutLastAccount(tx, value)
		return err
	})

	return err
}

func dbFetchLastAccount(db database.DB) (uint32, error) {

	var lastAcct uint32
	err := db.View(func(tx database.Tx) error {
		var err error
		lastAcct, err = walletdb.DbFetchLastAccount(tx)
		return err
	})

	return lastAcct, err
}

// GetAllAsset list all assets held by wallet
func (w *Wallet)GetAllAsset() (map[string]string,error){
	assets,err := walletdb.GetAllAsset(w.db)

	if err!=nil{
		return nil,err
	}
	return assets,nil
}












