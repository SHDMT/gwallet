package config

import (
	"path/filepath"

	"fmt"
	"github.com/SHDMT/gwallet/infrastructure/utils"
	"github.com/spf13/viper"
	"os"
)

const (
	defaultConfigFileName = "config.yaml"
	defaultDataDirName    = "data"
	defaultLogLevel       = "info"
	defaultLogDirName     = "log"
	defaultLogFileName    = "gwallet.log"
)

// gravity net type
const (
	NilNetType = iota
	// MainNetType use main network
	MainNetType
	// TestNetType use test network
	TestNetType
	// SimNetType use simulation test network
	SimNetType
	// MaxNetType supported Max net type
	MaxNetType
)

var (
	// DefaultHomeDir gWallet data save path
	DefaultHomeDir    = utils.AppDataPath("gwallet")
	defaultConfigFile = filepath.Join(DefaultHomeDir, defaultConfigFileName)
	defaultDataDir    = filepath.Join(DefaultHomeDir, defaultDataDirName)
	// DefaultLogDir gWallet log save path
	DefaultLogDir     = filepath.Join(DefaultHomeDir, defaultLogDirName)
	// DefaultLogFile gWallet log file name
	DefaultLogFile    = filepath.Join(DefaultHomeDir, defaultLogFileName)
)

// Params  details on the configuration .
type Params struct {
	DataDir string
	LogDir  string
	LogName string
	ClientName string

	LogLevel   int `yaml:"LogLevel"`
	MaxLogSize int `json:"MaxLogSize"`

	NetType int `yaml:"NetType"`

	HDPrivateKeyID [4]byte
	HDPublicKeyID  [4]byte
	HDCoinType     uint32


	Password string

	IsLight bool
}

// Parameters load
var Parameters *Params

func init() {
	err := LoadConfig()
	if err != nil {
		fmt.Println("load config err : ", err)
		//os.Exit(1)
	}
}
// LoadConfig load default configuration from the config.yaml
func LoadConfig() error {
	reader := viper.New()
	exist, err := utils.FileExists(defaultConfigFile)
	if err != nil {
		fmt.Println("load config err : ", err)
	}
	if !exist {
		os.Mkdir(DefaultHomeDir, os.ModePerm)
		//os.MkdirAll(defaultHomeDir,0766)
		conf := filepath.Join(DefaultHomeDir, "config.yaml")
		utils.CopyFile("./config.yaml", conf)
	}
	reader.SetConfigFile(defaultConfigFile)

	if err := reader.ReadInConfig(); nil != err {
		return err
	}

	Parameters = new(Params)
	err = reader.Unmarshal(Parameters)
	if err != nil {
		return err
	}
	Parameters.DataDir = defaultDataDir
	Parameters.HDPrivateKeyID = [4]byte{0x02, 0xfd, 0xa4, 0xe8}
	Parameters.HDPublicKeyID = [4]byte{0x02, 0xfd, 0xa9, 0x26}
	Parameters.HDCoinType = 80
	Parameters.NetType = 0
	return nil
}
