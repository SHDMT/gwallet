package utils

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"
)

func TestPathExists(t *testing.T) {
	path := "/Users/FLQ/Library/Application Support/gravity/config.yaml"
	exist, err := FileExists(path)
	if err != nil {
		fmt.Println("err : ", err)
	}
	fmt.Println("path exist : ", exist)
}

func TestCopyFile(t *testing.T) {
	defaultHomeDir := "/Users/FLQ/Library/Application Support/gwallet"
	conf := filepath.Join(defaultHomeDir, "appdata.go")
	fmt.Println("dest file : ", conf)
	n, err := CopyFile("./appdata.go", conf)
	if err != nil {
		fmt.Println("file copy err : ", err)
		return
	}
	fmt.Println("file copy ok : ", n)
}
func TestAppDataPath(t *testing.T) {

	if appDataPath("darwin", ".") != "." ||
		appDataPath("darwin", ".") != "." {
		t.Errorf("测试不通过")
	}

	appDataPath("darwin", "gravity")
	appDataPath("darwin", ".gravity")

	appDataPath("plan9", "gravity")
	appDataPath("plan9", ".gravity")

	appDataPath("windows", "gravity")
	appDataPath("windows", ".gravity")

	appDataPath("others", "gravity")
	appDataPath("others", ".gravity")
}

func TestBase64ToHex(t *testing.T) {
	base64Str := "zddJMGVOH+P9m/NgawHQ83Ntd7N9yPQvM/7tSg0oLj4="

	bytes, _ := base64.StdEncoding.DecodeString(base64Str)

	t.Logf("%x \n", bytes)
}

func TestHexToBase64(t *testing.T) {
	hexStr := "007be60593e6ac9e69826f69579771ec46d8b76ee99dcd2061e12344afff5761"
	bytes, _ := hex.DecodeString(hexStr)
	t.Logf("%s \n", base64.StdEncoding.EncodeToString(bytes))
}
