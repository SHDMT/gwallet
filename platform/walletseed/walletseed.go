package walletseed

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/SHDMT/gwallet/infrastructure/log"
	"strings"
	"unicode"
)

// Errors
var (
	ErrInvalidSeedLen = errors.New("seed length is invalid")
	ErrUnusableSeed = errors.New("unusable seed")
)
// SeedGenerator generate wallet seed
// return []byte and word list
func SeedGenerator() ([]byte, []string, error) {
	walletSeed, err := GenerateSeed(RecommendedSeedBytes)
	if err != nil {
		return nil, nil, err
	}
	seedStrSplit := EncodeMnemonicSlice(walletSeed)
	fmt.Println("Your wallet seed is:")
	for i := 0; i < RecommendedSeedBytes+1; i++ {
		fmt.Printf("%v ", seedStrSplit[i])

		if (i+1)%6 == 0 {
			fmt.Printf("\n")
		}
	}

	fmt.Printf("\n\nHex: %x\n", walletSeed)
	fmt.Println("IMPORTANT: Keep the seed in a safe place as you\n" +
		"will NOT be able to restore your wallet without it.")

	return walletSeed, seedStrSplit, nil
}

// GeneratorWalletSeed generate wallet seed
// return word list
func GeneratorWalletSeed() ([]string, error) {
	walletSeed, err := GenerateSeed(RecommendedSeedBytes)
	if err != nil {
		return nil, err
	}
	seedStrSplit := EncodeMnemonicSlice(walletSeed)
	return seedStrSplit, nil
}

// SeedRecover recover seed from exists word list
func SeedRecover(reader *bufio.Reader) ([]byte, error) {
	for {
		fmt.Print("Enter existing wallet seed " +
			"(followed by a blank line): ")

		seedStr, err := reader.ReadString('\n')
		if err != nil {
			return []byte(""), err
		}

		walletSeed, err := SeedValidate(seedStr)
		if err != nil {
			if err == ErrInvalidSeedLen {
				continue
			}
			return nil, err
		}
		return walletSeed, nil
	}
}

// SeedValidate Check if the seeds are legal
func SeedValidate(seedStr string) ([]byte, error) {

	seedStrTrimmed := strings.TrimSpace(seedStr)
	seedStrTrimmed = collapseSpace(seedStrTrimmed)
	wordCount := strings.Count(seedStrTrimmed, " ") + 1

	var walletSeed []byte
	var err error
	if wordCount == 1 {
		if len(seedStrTrimmed)%2 != 0 {
			seedStrTrimmed = "0" + seedStrTrimmed
		}
		walletSeed, err = hex.DecodeString(seedStrTrimmed)
		if err != nil {
			log.Errorf("Input error: %v\n", err.Error())
		}
	} else {
		walletSeed, err = DecodeUserInput(seedStrTrimmed)
		if err != nil {
			log.Errorf("Input error: %v\n", err.Error())
		}
	}
	if err != nil || len(walletSeed) < MinSeedBytes ||
		len(walletSeed) > MaxSeedBytes {
		log.Errorf("Invalid seed specified.  Must be a "+
			"word seed (usually 33 words) using the PGP wordlist or "+
			"hexadecimal value that is at least %d bits and "+
			"at most %d bits\n", MinSeedBytes*8,
			MaxSeedBytes*8)
		return nil, ErrInvalidSeedLen
	}

	log.Debug("\nSeed input successful. \nHex: %x\n", walletSeed)

	return walletSeed, nil
}

func collapseSpace(in string) string {
	whiteSpace := false
	out := ""
	for _, c := range in {
		if unicode.IsSpace(c) {
			if !whiteSpace {
				out = out + " "
			}
			whiteSpace = true
		} else {
			out = out + string(c)
			whiteSpace = false
		}
	}
	return out
}
