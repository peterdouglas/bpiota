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
	"github.com/NebulousLabs/hdkey/schnorr"
	"crypto/sha256"
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
	//seed2, err := ToTrytes("CLBHL9DOQXUHBWORNBHNPUB9JQUHYLLXXCJQRJVRJXYHAAISJPTDA9ZFVLPPNAHLDNMDDMGYXEDVROMQV")
	seed2, err := ToTrytes("CIXIFADSMGPA9HERAVAZMCUSEDJHKDKVYIEZNCAIYJQNHZNSHUEDSREQYIIMIQLTRPKPAFTAJX9FNNZBK")
	if err != nil {
		t.Error(err)
	}
	var (
		min int = 100
		max int = 0
	)
	addr2 := Address("BXHANKTHPJUPUVZOLJPZPQLDZPWVSBPGLMLSOYFZM9RSHVZRRBZJZJDZYTNRHXBVMQKFT9DVKVNDPCGC9")
	addC := string(addr2) + string(addr2.Checksum())
	fmt.Println(addC)
	for i:= 0; i < 5 ; i++  {
		addr := Address("")
		addr = addr.CreateAddress(seed2, i)

		length := len(addr)
		//fmt.Printf("Address %s is %s%s\n", i, addr, addr.Checksum())
		fmt.Printf("\"%s\",", addr)
		if length < min {
			min = length
		}

		if length > max {
			max = length
		}

	}
	fmt.Printf("The longest key is %v and the shortest key is %v", max, min)

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

func TestAddressing(t *testing.T) {
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
	testHashData := "TSIIPJNKJCKOLFD9P9UZCU9ZGAIFUOUASJXLHNQFGEWUHCSCPTXMTEUBAYHHNSXRMJTAZ99GTOOPC9BUW"
	//addressTrytes := Trytes("NDXCPBCB9BFCACEDOBCDFCRBOBKDBDXCRCBBNDCBCCWCUCCCZBSCFDXBNBJDKDHDRBVCTBGCZACDNDADFCZCHCID")
	//fmt.Printf("the seed is %s\n", seed)
	byteSeed, err := seed.Trits().Bytes()

	key, err := hdkey.NewMaster(byteSeed, nil, 1)
	if err != nil {
		log.Fatal(err)
	}

	secKey, err := key.SecretKey()

	childKey, err := key.Child(3)
	if err != nil {
		t.Error(err)
	}
	childSec, err := childKey.SecretKey()
	if err != nil {
		t.Error(err)
	}

	//hash := sha256.Sum256([]byte(testHashData))
	sig, err := schnorr.Sign(secKey,[]byte(testHashData))
	sig2, err := schnorr.Sign(childSec,[]byte(testHashData))
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

	err = schnorr.Verify(rebSig, key.PublicKey(), []byte(testHashData))
	err = schnorr.Verify(sig2, key.PublicKey(), []byte(testHashData))

	if err != nil {
		t.Error("Failed to verify signature")
	}

}


func TestKeygen(t *testing.T) {
	seed := Trytes("CLBHL9DOQXUHBWORNBHNPUB9JQUHYLLXXCJQRJVRJXYHAAISJPTDA9ZFVLPPNAHLDNMDDMGYXEDVROMQV")
	addressTrytes := Trytes("UYUNFEZOOIMJJOMBXZTSRK9BNXVDCLEJFTZTJVHYPNUFG9HDXGRSIEIJDGXIGAMJOQMHJATQXLCSUKAD9")


	addr, err := NewAddress(seed, 1)
	if err != nil {
		log.Fatal(err)
	}

	// serialize public key
	//pkCompressed := secKey.PublicKey().Compress()
	byteKey, err := addressTrytes.Trits().Bytes()
	if err != nil {
		t.Errorf("Error converting from trytes %s\n", err)
	}


	byteKey2, err := Trytes(addr).Trits().Bytes()
	if err != nil {
		t.Errorf("Error converting from trytes %s\n", err)
	}



	pkKey, err := secp256k1.ParsePubKey(byteKey[:33])
	if err != nil {
		t.Errorf("Error decoding Public Key, %s\n", err)
	}



	pkKey2, err := secp256k1.ParsePubKey(byteKey2[:33])
	//pkKey2, err := eckey.NewCompressedPublicKey(byteKey2[:33])
	if err != nil {
		t.Errorf("Error decoding Public Key, %s\n", err)
	}

	if (pkKey2.X.Cmp(pkKey.X) + pkKey2.Y.Cmp(pkKey.Y)) != 0 {
		t.Error("Keys did not match")
	}
}

func TestSigningFromKeyGen(t *testing.T) {
	seed := Trytes("CLBHL9DOQXUHBWORNBHNPUB9JQUHYLLXXCJQRJVRJXYHAAISJPTDA9ZFVLPPNAHLDNMDDMGYXEDVROMQV")
	//addressTrytes := Trytes("UYUNFEZOOIMJJOMBXZTSRK9BNXVDCLEJFTZTJVHYPNUFG9HDXGRSIEIJDGXIGAMJOQMHJATQXLCSUKAD9")
	hash := Trytes("TSIIPJNKJCKOLFD9P9UZCU9ZGAIFUOUASJXLHNQFGEWUHCSCPTXMTEUBAYHHNSXRMJTAZ99GTOOPC9BUW")

	seedBytes, err := seed.Trits().Bytes()
	mKey, err := hdkey.NewMaster(seedBytes, nil, 1)
	if err != nil {
		log.Fatal(err)
	}

	secKey, err := mKey.SecretKey()
	//secByte := secKey[:]
	//pubKey, err := mKey.Child(1)
	if err != nil {
		log.Fatal(err)
	}

	//sk, pk := secp256k1.PrivKeyFromBytes(secByte)


	sha256.New()
	hashSh := sha256.Sum256([]byte(hash))
	sig, err := schnorr.Sign(secKey, hashSh[:] )
	if err != nil {
		log.Fatal(err)
	}

	sigTrytes, err := AsciiToTrytes(base58.Encode(sig[:]))
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Printf("Signature is %s\n", sigTrytes)
	}

	rebuilt, err := TrytesToAscii(sigTrytes)
	if err != nil {
		log.Fatal(err)
	}

	sha256.New()
	hashSh2 := sha256.Sum256([]byte(hash))
	sigReb := new(schnorr.Signature)
	copy(sigReb[:], base58.Decode(rebuilt))
	err = schnorr.Verify(sigReb, secKey.PublicKey(), hashSh2[:])
	if err != nil {
		t.Errorf("Sig %s\n failed %s", sigReb[:], sig[:])
	}

	// serialize public key
	//pkCompressed := secKey.PublicKey().Compress()
	//byteKey, err := addressTrytes.Trits().Bytes()
	if err != nil {
		t.Errorf("Error converting from trytes %s\n", err)
	}


}