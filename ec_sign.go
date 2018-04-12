/*
MIT License

Copyright (c) 2016 Sascha Hanse
Copyright (c) 2017 Shinya Yagyu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package giota

import (
	"github.com/decred/dcrd/dcrec/secp256k1"
	"log"
	"github.com/NebulousLabs/hdkey"
	"github.com/decred/base58"
	"fmt"
	"unicode/utf8"
	"strings"
	"math/big"
)

var (
	mKey *hdkey.HDKey = nil
)


// NewSeed generate a random Trytes
func NewECSeed() (Trytes, error) {
	secretKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		log.Fatal(err)
		return "", err
	}
	hdkey.GenerateSeed(16)

	stringSec := base58.Encode(secretKey.GetD().Bytes());
	return ToTrytes(stringSec)
}



// NewKey takes a seed encoded as Trytes, an index and a security
// level to derive a private key returned as Trytes
func NewPublicKey(seed Trytes, index int) (Trytes, error) {
	bytesSec, err := seed.Trits().Bytes()
	if err != nil {
		return "", err
	}

	if mKey == nil {
		key, err := hdkey.NewMaster(bytesSec, nil, 1)
		if err != nil {
			return "", err
		}
		mKey = key
	}

	pubKey, err := mKey.Child(uint32(index))
	if err != nil {
		return "", err
	}

	pkCompressed := pubKey.PublicKey().Compress()
	pkInt := new(big.Int).SetBytes(pkCompressed[:])
	keyTrit := make([]byte, 48)
	copy(keyTrit, pkInt.Bytes())
	trits, err := BytesToTrits(keyTrit)
	if err != nil {
		return "", err
	}

	return trits.Trytes(), err
}

func NewAddress(seed Trytes, index int) (Address, error) {
	tryteAdd, err := NewPublicKey(seed, index)
	if err != nil {
		return "", err
	}
	addr, err := tryteAdd.ToAddress()

	if err != nil {
		return "", err
	}
	return addr, nil
}

func NewAddresses(seed Trytes, start, stop int) ([]Address, error) {
	var addresses []Address
	for i := start; i <= stop ; i++  {
		tempAddr, err := NewAddress(seed, i)
		if err != nil {
			return addresses, err
		}
		addresses = append(addresses, tempAddr)
	}

	return addresses, nil
}

func AsciiToTrytes(input string) (Trytes, error) {
	var tempOutput string
	var err error

	for key, charCode := range input {
		if charCode > 255 {
			err = fmt.Errorf("Error, char %s was above 255 in position %s\n", charCode, key)
			err.Error()
		} else {
			firstVal := charCode % 27
			secondVal := (charCode - firstVal) / 27
			tryteVal := string(TryteAlphabet[firstVal]) + string(TryteAlphabet[secondVal])
			tempOutput += tryteVal
		}
	}
	tryteOut, err := ToTrytes(tempOutput)

	return tryteOut, err
}

func TrytesToAscii(input Trytes) (string, error) {
	var tempOutput string
	var err error
	if len(input) % 2 != 0 {
		err = fmt.Errorf("Length was not divisble by 2, invalid tryte")
		return "", err
	}

	for i := 0; i < len(input); i+= 2  {
		firstVal, _ := utf8.DecodeRuneInString(string(input[i:]))
		secondVal, _ := utf8.DecodeRuneInString(string(input[i + 1:]))
		//firstVal := TryteAlphabet[tempTryte[0]]
		ind1 := strings.Index(TryteAlphabet, string(firstVal))
		ind2 := strings.Index(TryteAlphabet, string(secondVal))
		decimalVal := ind1 + ind2 * 27
		tempByte := make([]byte, 1)
		_ = utf8.EncodeRune(tempByte, rune(decimalVal))
		tempOutput += string(tempByte)
	}

	return tempOutput, err
}