package walletseed

import (
	"encoding/hex"
	"testing"
)

func TestGenerateSeed(t *testing.T) {

	// -------------------- case 1 generate seed
	seed, err := GenerateSeed(RecommendedSeedBytes)
	if err != nil {
		t.Error("test : generate seed failed.")
	}
	t.Logf("seed : %x \n", seed)
	t.Logf("test : generate seed succeed.\n")

	// --------------------case 2 generate seed with invalid seed length
	_, err = GenerateSeed(MinSeedBytes - 1)
	if err != nil {
		t.Log("test case2 : generate seed succeed .")
	} else {
		t.Error("test case2 : generate seed failed .")
	}

	// --------------------case 3 generate seed with invalid seed length
	_, err = GenerateSeed(MaxSeedBytes + 1)
	if err != nil {
		t.Log("test case2 : generate seed succeed .")
	} else {
		t.Error("test case2 : generate seed failed .")
	}
}

func TestEncodeMnemonicSlice(t *testing.T) {

	seedHex := "20aa71da631cde2bc6e1f6969e69c2b0d3fed1216bf09ad91d596f4aeb444215"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Error(" can't decoded hex string ")
		return
	}

	list := EncodeMnemonicSlice(seed)
	t.Logf(" word list : %+v \n", list)
}

func TestDecodeUserInput(t *testing.T) {
	// ----------------- case 1 : test DecodeUserInput
	wordStr := "bison pedigree hamlet surrender flatfoot Brazilian tactics Cherokee southward tolerance village monument quiver guitarist snapshot phonetic stapler yesteryear stairway Camelot glitter upcoming pupil supportive Belfast examine gremlin direction trouble designing crowfoot bifocals flatfoot"

	seed, err := DecodeUserInput(wordStr)
	if err != nil {
		t.Error(" test decodeUserInput failed : ", err)
	}
	t.Logf(" seed : %x \n", seed)
	t.Log(" case 1 : test decodeUserInput succeed .")

	// ------------------ case 2: test DecodeUserInput with invalid wordlist
	wordStr1 := "bison pedigree hamlet surrender flatfoot Brazilian tactics Cherokee southward usdf tolerance village monument quiver guitarist snahot phonetic stapler yesteryear stairway Camelot glitter upcoming pupil supportive Belfast examine gremlin direction trouble designing crowfoot bifocals flatfoot"

	_, err = DecodeUserInput(wordStr1)
	if err != nil {
		t.Log(" case 2 : test decodeUserInput succeed ")
	}

	// ----------------- case 3: test DecodeUserInput with hex seed
	wordStr2 := "20aa71da631cde2bc6e1f6969e69c2b0d3fed1216bf09ad91d596f4aeb444215"
	seed, err = DecodeUserInput(wordStr2)
	if err != nil {
		t.Error(" test decodeUserInput failed : ", err)
	}
	t.Logf(" seed : %x \n", seed)
	t.Log(" case 1 : test decodeUserInput succeed .")
}
