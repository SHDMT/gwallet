package addrmgr

import (
	"bytes"
	"encoding/hex"
	"github.com/SHDMT/gwallet/infrastructure/config"
	"testing"
)

func TestNewWIF(t *testing.T) {

	privKeyStr := "4736316c34888805f5a5790e724b7129bf4c1670bd26356772182bb49fbde8a0"
	privKeyBytes, err := hex.DecodeString(privKeyStr)
	if err != nil {
		t.Error("hex decoded failed. ")
	}
	wif, err := NewWIF(privKeyBytes, config.Parameters, SECP256K1)
	if err != nil {
		t.Error("create wif failed.")
	}

	if bytes.Equal(wif.PrivKey, privKeyBytes) {
		t.Log("test create wif succeed")
	}
}

func TestWIF_IsForNet(t *testing.T) {
	wifStr := "11111112SEe6qhJ11bboJPH8HNUxaDY4j2vF3LDGDriyn2HXJ1WevEBRFN82khKEvGDk"
	var wif WIF
	err := wif.ParseWIF(wifStr)
	if err != nil {
		t.Error(" parse wif private key failed.")
		return
	}
	result := wif.IsForNet(config.Parameters)
	if result {
		t.Log("test IsForNet succeed.")
	} else {
		t.Error("test IsForNet failed. ")
	}

	wifStr2 := "22222222SEe6qhJ11bb72q9zVpd6x9KhZvrk9QaTif89y1mQ3rKmZXJhjbyVoA72mx1J"
	var wif2 WIF
	err = wif2.ParseWIF(wifStr2)
	if err != nil {
		t.Log("test IsForNet succeed.")
		return
	}
}

func TestWIF_String(t *testing.T) {
	wifStr := "11111112SEe6qhJ11bboJPH8HNUxaDY4j2vF3LDGDriyn2HXJ1WevEBRFN82khKEvGDk"
	var wif WIF
	err := wif.ParseWIF(wifStr)
	if err != nil {
		t.Error(" parse wif private key failed.")
		return
	}
	dumpStr := wif.String()
	if wifStr == dumpStr {
		t.Log(" test encoding wif private key succeed. ")
	} else {
		t.Error(" test encoding wif private key failed. ")
		return
	}
}

func TestWIF_ParseWIF(t *testing.T) {

	wifStr := "11111112SEe6qhJ11bboJPH8HNUxaDY4j2vF3LDGDriyn2HXJ1WevEBRFN82khKEvGDk"
	var wif WIF
	err := wif.ParseWIF(wifStr)
	if err != nil {
		t.Error(" parse wif private key failed.")
		return
	}
	t.Log("test parse wif privatekey succeed")
}
