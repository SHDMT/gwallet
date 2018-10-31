package dbnamespace

//bucket name
var (

	KeyPairsBucket = []byte("publicKey-privateKey")

	AddrPubBucket = []byte("address-publicKey")

	AddressBucket = []byte("address")

	MessageBucket = []byte("message")

	MessageIndexBucket = []byte("m-index")

	UtxoBucket = []byte("utxo")

	LastMciBucket = []byte("lastMci")

	MasterKeyBucket = []byte("masterKey")

	CryptoKeyBucket = []byte("cryptoKey")

	CoinTypeKeyBucket = []byte("coinTypeKey")

	AccountInfoBucket = []byte("accountInfo")

	AccountBucket = []byte("name-account")

	AccountNameBucket = []byte("account-name")

	LastAccountBucket = []byte("lastAccount")

	LastUsedAccountBucket = []byte("lastUsedAccount")

	SecretKeyBucket = []byte("secretKey")

	AssetBucket = []byte("assetID")

	AssetNameBucket = []byte("asset-name")

	NameAssetBucket = []byte("name-asset")
)

//Fixed key
var (
	LastMciKey = []byte{0, 0, 0, 0, 0, 0, 0, 0}

	UpdateKey = []byte("update")

	LastAccount = []byte("lastAccount")

	LastUsedAccount = []byte("lastUsedAccount")

	Crypto = []byte("cryptoPub")

	SecretKey = []byte("secretKey")
)
