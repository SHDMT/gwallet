package walletseed

import (
	"testing"
)

func TestSeedGenerator(t *testing.T) {

	seedHex, seedWord, err := SeedGenerator()
	if err != nil {
		t.Error(" test seed generate failed .")
		return
	}
	t.Logf(" Hex seed : %x \n", seedHex)
	t.Logf(" Word seed: %+v \n", seedWord)
	t.Log(" test seed generate succeed .")
}

func TestWalletSeedGenerator(t *testing.T) {
	word, err := GeneratorWalletSeed()
	if err != nil {
		t.Log(" test wallet seed generate failed .")
		return
	}
	t.Logf("wordlist : %+v \n ", word)
	t.Log(" test wallet seed generate succeed .")
}

func TestSeedValidate(t *testing.T) {
	seedStr := "bison pedigree hamlet surrender flatfoot Brazilian tactics Cherokee southward tolerance village monument quiver guitarist snapshot phonetic stapler yesteryear stairway Camelot glitter upcoming pupil supportive Belfast examine gremlin direction trouble designing crowfoot bifocals flatfoot"

	seed, err := SeedValidate(seedStr)
	if err != nil {
		t.Error(" case 1 : test seedValidate failed .")
	}
	t.Logf("seed : %x \n", seed)
	t.Log("case 1 : test seedValidate succeed .")

	// ------------------------- case 2 : validate with invalid wordlist
	wronfSeedStr := "bison pedigree hamlet surrender flatfoot Brazilian tacs Cherokee southward tolerance village monument quiver guitarist snapshot phonetic stapler yesteryear stairway Camelot glitter upcoming pupil supportive Belfast examine gremlin direction trouble designing crowfoot bifocals flatfoot"

	_, err = SeedValidate(wronfSeedStr)
	if err != nil {
		t.Log(" case 2 : test seedValidate succeed .")
	}

	// ------------------------- case 3 : validate with hex seed
	hexSeedStr := "20aa71da631cde2bc6e1f6969e69c2b0d3fed1216bf09ad91d596f4aeb444215"
	seed, err = SeedValidate(hexSeedStr)
	if err != nil {
		t.Error(" case 3 : test seedValidate failed .")
		return
	}
	t.Logf("seed : %x \n", seed)
	t.Log("case 3 : test seedValidate succeed .")

	// ------------------------- case 4 : validate with wrong hex seed
	hexSeedStr2 := "20aa71da631cde2bc6e1f6969e69c2b0d3fed1216bf9ad91d596f4aeb444215"
	seed, err = SeedValidate(hexSeedStr2)
	if err != nil {
		t.Log("case 4 : test seedValidate succeed .")
	}

	// ------------------------- case 5 : validate with wrong hex seed
	hexSeedStr3 := "20aa71da631cde2bc6e1f6969e69c2b0d3fed1216bf09ad91d596f4aeb44421s"
	seed, err = SeedValidate(hexSeedStr3)
	if err != nil {
		t.Log("case 5 : test seedValidate succeed .")
		return
	}
	t.Error(" case 5 : test seedValidate failed .")
}
