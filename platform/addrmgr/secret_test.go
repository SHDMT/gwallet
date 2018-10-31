package addrmgr

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestCryptoKey_Zero(t *testing.T) {
	cryptokey, err := GenerateCryptoKey()
	if err != nil {
		t.Error(" cryptokey test : generate crypto key failed :", err)
		return
	}
	cryptokey.Zero()
	zeroByte := make([]byte, KeySize)
	if bytes.Equal(zeroByte, cryptokey.Bytes()) {
		t.Log(" cryptokey test : zero cryptokey succeed .")
	} else {
		t.Log(" cryptokey test : zero cryptokey failed .")
	}
}

func TestCryptoKey_Encrypt(t *testing.T) {
	cryptokey, err := GenerateCryptoKey()
	if err != nil {
		t.Error(" cryptokey test : generate crypto key failed : ", err)
		return
	}
	plainText := " this is test string"
	dataEnc, err := cryptokey.Encrypt([]byte(plainText))
	if err != nil {
		t.Error(" cryptokey test : encrypt failed : ", err)
		return
	}
	t.Logf("cipher text is : %x \n", dataEnc)
	t.Log("cryptokey test :  encrypt succeed .\n")

	data, err := cryptokey.Decrypt(dataEnc)
	if err != nil {
		t.Error(" cryptokey test : decrypt failed : ", err)
		return
	}
	if string(data) == plainText {
		t.Log("cryptokey test : decrypt succeed . ")
	} else {
		t.Log("cryptokey test : decrypt failed . ")
	}
}

func TestGenerateCryptoKey(t *testing.T) {

	cryptoKey, err := GenerateCryptoKey()
	if err != nil {
		t.Error(" cryptokey test : generate key failed : ", err)
		return
	}
	t.Logf(" cryptoKey is : %x \n", cryptoKey.Bytes())
	t.Log(" cryptokey test : generate key succeed .")
}

func TestSecretKey_DeriveKey(t *testing.T) {

	passwordStr := "pass"
	password := []byte(passwordStr)
	secretkey, err := NewSecretKey(&password, DefaultN, DefaultR, DefaultP)
	if err != nil {
		t.Error(" test : create new secret key failed . ")
		return
	}

	//-------------------------------------------------------------------------------
	err = secretkey.DeriveKey(&password)
	if err != nil {
		t.Error(" secretkey test : derive key failed : ", err)
		return
	}
	t.Log(" secretkey test : derive key succeed .\n")

	//-------------------------------------------------------------------------------
	wrongpass := "wrongpass"
	wrongpassword := []byte(wrongpass)
	err = secretkey.DeriveKey(&wrongpassword)
	if err != nil {
		t.Log(" secretkey test : derive key succeed .")
	} else {
		t.Error(" secretkey test : derive key failed .")
	}
}

func TestSecretKey_Marshal(t *testing.T) {

	passwordStr := "pass"
	password := []byte(passwordStr)
	secretkey, err := NewSecretKey(&password, DefaultN, DefaultR, DefaultP)
	if err != nil {
		t.Error(" test : create new secret key failed . ")
		return
	}

	secretkeyBytes := secretkey.Marshal()
	t.Logf(" secretkey bytes : %x \n", secretkey)

	var newSecretKey SecretKey
	err = newSecretKey.Unmarshal(secretkeyBytes)
	if err != nil {
		t.Error(" secretkey test : unmarshal failed : ", err)
		return
	}
}

func TestSecretKey_Encrypt(t *testing.T) {

	passwordStr := "pass"
	password := []byte(passwordStr)
	secretkey, err := NewSecretKey(&password, DefaultN, DefaultR, DefaultP)
	if err != nil {
		t.Error(" test : create new secret key failed . ")
		return
	}
	t.Logf(" your secretkey is : %x \n", secretkey.Marshal())

	data := "this is a test string"
	dataEnc, err := secretkey.Encrypt([]byte(data))
	if err != nil {
		t.Error(" secretkey test: encrypt failed . ")
		return
	}
	t.Logf(" cipher data is : %x \n", dataEnc)
	t.Log(" secretkey test : encrypt succeed . ")

	dataDec, err := secretkey.Decrypt(dataEnc)
	if err != nil {
		t.Error(" secretkey test : decrypt failed : ", err)
		return
	}
	if string(dataDec) == data {
		t.Log(" secretkey test : decrypt succeed \n")
	} else {
		t.Log(" secretkey test : decrypt failed \n")
		return
	}
}

func TestSecretKey_Decrypt(t *testing.T) {
	//---------------------------------decoded for true password--------------------------------------------------
	passwordStr := "pass"
	password := []byte(passwordStr)
	keyStr := "b02c9f7bb24a32b7127899e0a9c1f96d5cd0ce2a09621539087632851ae4ec13d0578a316f3193bccb5554340dfb7082a54a2f2b4ee2f56b5fe6828bedd20563000004000000000008000000000000000100000000000000"
	secretkeyBytes, err := hex.DecodeString(keyStr)
	if err != nil {
		t.Error(" hex string decoded failed : ", err)
		return
	}

	var newSecretKey SecretKey
	err = newSecretKey.Unmarshal(secretkeyBytes)
	if err != nil {
		t.Error(" secret key unmashal failed : ", err)
		return
	}

	err = newSecretKey.DeriveKey(&password)
	if err != nil {
		t.Error(" can't derive secret key : ", err)
	}

	dataEncStr := "d84326bb2e0b3ab0b2bd0c836ff0663adaa6c7e884d06479835b53e27863bdceaaaa0a5cad52b1fa2559ed74259652caed4799ec0c92456c6b966aba3e"
	dataEnc, err := hex.DecodeString(dataEncStr)
	if err != nil {
		t.Error(" can't decoded hex string : ", err)
		return
	}

	data, err := newSecretKey.Decrypt(dataEnc)
	if err != nil {
		t.Error(" secretkey test : decrypt failed : ", err)
		return
	}
	if string(data) == "this is a test string" {
		t.Log(" test decrypt cipher data with true password : succeed \n")
	} else {
		t.Log(" test decrypt cipher data with true password : failed \n")
		return
	}

	//---------------------------------decoded for true password--------------------------------------------------
	wrongPass := "pass111"
	wrongPassword := []byte(wrongPass)

	var case2Key SecretKey
	err = case2Key.Unmarshal(secretkeyBytes)
	if err != nil {
		t.Error(" secret key unmarshal failed : ", err)
		return
	}

	err = case2Key.DeriveKey(&wrongPassword)
	if err != nil {
		t.Log(" test decrypt cipher data with wrong password : succeed \n")
	} else {
		t.Log(" test decrypt cipher data with wrong password : failed \n")
		return
	}

	//---------------------------------decoded for true password--------------------------------------------------
	wrongKeyStr := "b02c9f7bb24a32b7127899e0a9c1f96d5cd0ce2a09621539087632881ae4ec13d0578a316f3193bccb5554340dfb7082a54a2f2b4ee2f56b5fe6828bedd20563000004000000000008000000000000000100000000000000"
	wrongSecretkeyBytes, err := hex.DecodeString(wrongKeyStr)
	if err != nil {
		t.Error(" hex string decoded failed : ", err)
		return
	}

	var case3Key SecretKey
	err = case3Key.Unmarshal(wrongSecretkeyBytes)
	if err != nil {
		t.Error(" secret key unmarshal failed : ", err)
		return
	}

	err = case3Key.DeriveKey(&password)
	if err != nil {
		t.Log(" test decrypt cipher data with wrong secretkey : succeed \n")
	} else {
		t.Log(" test decrypt cipher data with wrong secretkey : failed \n")
		return
	}
}

func TestNewSecretKey(t *testing.T) {

	passwordStr := "pass"
	password := []byte(passwordStr)
	secretkey, err := NewSecretKey(&password, DefaultN, DefaultR, DefaultP)
	if err != nil {
		t.Error(" test : create new secret key failed . ")
		return
	}
	t.Logf(" secret key is : %+v \n", secretkey)
	t.Log(" test : create new secret key succeed . ")
}
