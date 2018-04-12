package giota

import (
	"testing"
	"log"
	"github.com/NebulousLabs/hdkey"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/NebulousLabs/hdkey/eckey"
	"math/big"
	"github.com/decred/base58"
	"crypto/sha256"
	"github.com/NebulousLabs/hdkey/schnorr"
)

func TestNewECSeed(t *testing.T) {
	seed := NewSeed()
	fmt.Printf("the seed is %s/n", seed)
	byteSeed, err := seed.Trits().Bytes()

	key, err := hdkey.NewMaster(byteSeed, nil, 1)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Secret key is : %s/n", key.String())

	key1, err := key.Child(1)
	fmt.Printf("Second key is : %s/n", key1.String())

}

func TestKeyGeneration(t *testing.T) {
	seed := Trytes("CLBHL9DOQXUHBWORNBHNPUB9JQUHYLLXXCJQRJVRJXYHAAISJPTDA9ZFVLPPNAHLDNMDDMGYXEDVROMQV")
	fmt.Printf("the seed is %s", seed)
	byteSeed, err := seed.Trits().Bytes()

	key, err := hdkey.NewMaster(byteSeed, nil, 1)
	if err != nil {
		log.Fatal(err)
	}

	secKey, err := key.SecretKey()

	privKey, _ :=secp256k1.PrivKeyFromBytes(secKey[:])
	//fmt.Printf("First public key from gen key is :  %s\n", secKey.PublicKey().Compress())
	sec2, _ := eckey.NewSecretKey(privKey.GetD().Bytes())
	//fmt.Printf("First public key from rebuilt key is :  %s\n", sec2.PublicKey().Compress())
	if string(sec2[:]) != string(secKey[:]) {
		t.Errorf("Regenerated key did not match initial key")
	}

}

func TestPubKeyGeneration(t *testing.T) {
	seed, err := ToTrytes("CLBHL9DOQXUHBWORNBHNPUB9JQUHYLLXXCJQRJVRJXYHAAISJPTDA9ZFVLPPNAHLDNMDDMGYXEDVROMQV")
	if err != nil {
		t.Error(err)
	}

	newKey, err := NewPublicKey(seed, 1)
	if err != nil {
		t.Error(err)
	}

	nKey2, err := NewPublicKey(seed, 1)
	if err != nil {
		t.Error(err)
	}

	if string(newKey) != string(nKey2) {
		t.Errorf("Regenerated key did not match initial key, %s \n %s\n", newKey, nKey2)
	}

}

func TestEncoding(t *testing.T) {
	seed := Trytes("CLBHL9DOQXUHBWORNBHNPUB9JQUHYLLXXCJQRJVRJXYHAAISJPTDA9ZFVLPPNAHLDNMDDMGYXEDVROMQV")
	addressTrytes := Trytes("UYUNFEZOOIMJJOMBXZTSRK9BNXVDCLEJFTZTJVHYPNUFG9HDXGRSIEIJDGXIGAMJOQMHJATQXLCSUKAD9")
	fmt.Printf("the seed is %s\n", seed)
	byteSeed, err := seed.Trits().Bytes()

	key, err := hdkey.NewMaster(byteSeed, nil, 1)
	if err != nil {
		log.Fatal(err)
	}

	secKey, err := key.SecretKey()


	// serialize public key
	pkCompressed := secKey.PublicKey().Compress()
	pkInt := new(big.Int).SetBytes(pkCompressed[:])
	pkStr := string(pkCompressed[:])
	println(pkStr)
	println(len([]byte(pkInt.Text(10))))
	println(len([]byte(pkInt.Text(62))))
	println(len(pkInt.Bytes()))
	keyTrit := make([]byte, 48)
	copy(keyTrit, pkInt.Bytes())
	trits, err := BytesToTrits(keyTrit)
	if err != nil {
		t.Error(err)
	}
	println(trits.Trytes())
	tritByte, err := trits.Bytes()
	if err != nil {
		t.Error(err)
	}

	pk2Int := new(big.Int).SetBytes(tritByte[:33])

	addressS := base58.Encode(pkInt.Bytes())
	address2 := base58.Encode(pk2Int.Bytes())
	addressT, err :=  AsciiToTrytes(addressS)
	if err != nil {
		t.Errorf("Error converting to trytes %s\n", err)
	}

	if addressT != addressTrytes {
		t.Error("The generated address does not match")
	} else {
		fmt.Printf("The address is %s\n and %s\n", addressS, address2)
	}

}

func TestAddressLength(t *testing.T) {
	seed, err := ToTrytes("CLBHL9DOQXUHBWORNBHNPUB9JQUHYLLXXCJQRJVRJXYHAAISJPTDA9ZFVLPPNAHLDNMDDMGYXEDVROMQV")
	if err != nil {
		t.Error(err)
	}
	var (
		min int = 100
		max int = 0
	)

	for i:= 1; i < 5 ; i++  {
		newKey, err := NewPublicKey(seed, i)
		if err != nil {
			t.Error(err)
		}

		length := len(newKey)
		fmt.Printf("Address %s is %s\n", i, newKey)
		if length < min {
			min = length
		}

		if length > max {
			max = length
		}

	}
	fmt.Printf("The longest key is %s and the shortest key is %s", max, min)

}

func TestDecoding(t *testing.T) {
	seed := Trytes("CLBHL9DOQXUHBWORNBHNPUB9JQUHYLLXXCJQRJVRJXYHAAISJPTDA9ZFVLPPNAHLDNMDDMGYXEDVROMQV")
	addressTrytes := Trytes("UYUNFEZOOIMJJOMBXZTSRK9BNXVDCLEJFTZTJVHYPNUFG9HDXGRSIEIJDGXIGAMJOQMHJATQXLCSUKAD9")

	byteSeed, err := seed.Trits().Bytes()
	key, err := hdkey.NewMaster(byteSeed, nil, 1)
	if err != nil {
		log.Fatal(err)
	}

	secKey, err := key.SecretKey()

	// serialize public key
	//pkCompressed := secKey.PublicKey().Compress()
	byteKey, err := addressTrytes.Trits().Bytes()
	if err != nil {
		t.Errorf("Error converting from trytes %s\n", err)
	}



	pkKey, err := secp256k1.ParsePubKey(byteKey[:33])
	if err != nil {
		t.Errorf("Error decoding Public Key, %s\n", err)
	}

	pkx, pky := secKey.PublicKey().Coords()

	if (pkx.Cmp(pkKey.X) + pky.Cmp(pkKey.Y)) != 0 {
		t.Error("Keys did not match")
	}
}

func TestAddessing(t *testing.T) {
	addressTrytes := Trytes("UYUNFEZOOIMJJOMBXZTSRK9BNXVDCLEJFTZTJVHYPNUFG9HDXGRSIEIJDGXIGAMJOQMHJATQXLCSUKAD9")
	addressWithCS := Trytes("UYUNFEZOOIMJJOMBXZTSRK9BNXVDCLEJFTZTJVHYPNUFG9HDXGRSIEIJDGXIGAMJOQMHJATQXLCSUKAD9GCBUTFUBD")
	addr, err := addressTrytes.ToAddress()
	if err != nil {
		t.Errorf("There was an error with the address %s\n", err)
	}
	checkS := addr.WithChecksum()

	if addressWithCS != checkS {
		t.Error("The checksums did not match")
	}
	fmt.Printf("The checksum is %s\n", checkS)
}

func TestECSign(t *testing.T) {
	seed := Trytes("CLBHL9DOQXUHBWORNBHNPUB9JQUHYLLXXCJQRJVRJXYHAAISJPTDA9ZFVLPPNAHLDNMDDMGYXEDVROMQV")
	testHashData := "Thisisthetestdata"
	//addressTrytes := Trytes("NDXCPBCB9BFCACEDOBCDFCRBOBKDBDXCRCBBNDCBCCWCUCCCZBSCFDXBNBJDKDHDRBVCTBGCZACDNDADFCZCHCID")
	//fmt.Printf("the seed is %s\n", seed)
	byteSeed, err := seed.Trits().Bytes()

	key, err := hdkey.NewMaster(byteSeed, nil, 1)
	if err != nil {
		log.Fatal(err)
	}

	secKey, err := key.SecretKey()

	hash := sha256.Sum256([]byte(testHashData))

	sig, err := schnorr.Sign(secKey, hash[:])
	fmt.Printf("Sig1 is %x\n", sig)
	if err != nil {
		t.Error("The signature has failed")
	}
	tryteSig, err := AsciiToTrytes(base58.Encode(sig[:]))
	fmt.Printf("Signature is %s\n", tryteSig)
	rebuilt, err := TrytesToAscii(tryteSig)
	rebSig := new(schnorr.Signature)
	copy(rebSig[:], base58.Decode(rebuilt))
	fmt.Printf("Sig2 is %x\n", rebSig)

	err = schnorr.Verify(rebSig, key.PublicKey(), hash[:])

	if err != nil {
		t.Error("Failed to verify signature")
	}

}



