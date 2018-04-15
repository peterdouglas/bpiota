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
	"crypto/rand"
	"errors"
	"math/big"
	"log"
	"github.com/NebulousLabs/hdkey/eckey"
	"fmt"
	"crypto/sha256"
	"github.com/NebulousLabs/hdkey/schnorr"
	"github.com/decred/base58"
)

// errors used in sign
var (
	ErrSeedTritsLength  = errors.New("seed trit slice should be HashSize entries long")
	ErrSeedTrytesLength = errors.New("seed string needs to be HashSize / 3 characters long")
	ErrKeyTritsLength   = errors.New("key trit slice should be a multiple of HashSize*27 entries long")
)

// NewSeed generate a random Trytes
func NewSeed() Trytes {
	b := make([]byte, 49)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	txt := new(big.Int).SetBytes(b).Text(27)
	t := make([]byte, 81)
	for i := range t {
		var c byte = '0'
		if len(txt) > i {
			c = txt[i]
		}
		if c == '0' {
			t[i] = '9'
		}
		if c >= '1' && c <= '9' {
			t[i] = c - '1' + 'A'
		}
		if c >= 'a' {
			t[i] = c - 'a' + ('A' + 9)
		}
	}
	return Trytes(t)
}

// newKeyTrits takes a seed encoded as Trytes, an index and a security
// level to derive a private key returned as Trits
func newKeyTrits(seed Trytes, index, securityLevel int) (Trits, error) {
	if err := seed.IsValid(); err != nil {
		return nil, err
	} else if len(seed) != TritHashLength/Radix {
		return nil, ErrSeedTrytesLength
	}

	seedTrits := seed.Trits()
	// Utils.increment
	for i := 0; i < index; i++ {
		incTrits(seedTrits)
	}

	k := NewKerl()
	err := k.Absorb(seedTrits)
	if err != nil {
		return nil, err
	}

	hashedTrits, _ := k.Squeeze(HashSize)
	k.Reset()
	err = k.Absorb(hashedTrits)
	if err != nil {
		return nil, err
	}

	key := make(Trits, (HashSize * 27 * securityLevel))

	for l := 0; l < securityLevel; l++ {
		for i := 0; i < 27; i++ {
			b, _ := k.Squeeze(HashSize)
			copy(key[(l*27+i)*HashSize:], b)
		}
	}

	return key, nil
}

// NewKey takes a seed encoded as Trytes, an index and a security
// level to derive a private key returned as Trytes
func NewKey(seed Trytes, index, securityLevel int) (Trytes, error) {
	ts, err := newKeyTrits(seed, index, securityLevel)
	return ts.Trytes(), err
}

func clearState(l *[stateSize]uint64, h *[stateSize]uint64) {
	for j := HashSize; j < stateSize; j++ {
		l[j] = 0xffffffffffffffff
		h[j] = 0xffffffffffffffff
	}
}

// 01:-1 11:0 10:1
func para27(in Trytes) (*[stateSize]uint64, *[stateSize]uint64) {
	var l, h [stateSize]uint64

	clearState(&l, &h)
	var j uint
	bb := in.Trits()
	for i := 0; i < HashSize; i++ {
		for j = 0; j < 27; j++ {
			l[i] <<= 1
			h[i] <<= 1
			switch bb[int(j)*HashSize+i] {
			case 0:
				l[i] |= 1
				h[i] |= 1
			case 1:
				l[i] |= 0
				h[i] |= 1
			case -1:
				l[i] |= 1
				h[i] |= 0
			}
		}
	}
	return &l, &h
}

func seri27(l *[stateSize]uint64, h *[stateSize]uint64) Trytes {
	keyFragment := make(Trits, HashSize*27)
	r := make(Trits, HashSize)
	var n uint
	for n = 0; n < 27; n++ {
		for i := 0; i < HashSize; i++ {
			ll := (l[i] >> n) & 1
			hh := (h[i] >> n) & 1
			switch {
			case hh == 0 && ll == 1:
				r[i] = -1
			case hh == 1 && ll == 1:
				r[i] = 0
			case hh == 1 && ll == 0:
				r[i] = 1
			}
		}
		copy(keyFragment[(26-n)*HashSize:], r)
	}
	return keyFragment.Trytes()
}

// Digests calculates hash x 26 for each segment in keyTrits
func Digests(key Trits) (Trits, error) {
	if len(key) < HashSize*27 {
		return nil, ErrKeyTritsLength
	}

	// Integer division, becaue we don't care about impartial keys.
	numKeys := len(key) / (HashSize * 27)
	digests := make(Trits, HashSize*numKeys)
	buffer := make(Trits, HashSize)

	for i := 0; i < numKeys; i++ {
		k2 := NewKerl()
		for j := 0; j < 27; j++ {
			copy(buffer, key[i*SignatureSize+j*HashSize:i*SignatureSize+(j+1)*HashSize])

			for k := 0; k < 26; k++ {
				k := NewKerl()
				k.Absorb(buffer)
				buffer, _ = k.Squeeze(HashSize)
			}
			k2.Absorb(buffer)
		}
		buffer, _ = k2.Squeeze(HashSize)
		copy(digests[i*HashSize:], buffer)
	}
	return digests, nil
}

// digest calculates hash x normalizedBundleFragment[i] for each segment in keyTrits.
func digest(normalizedBundleFragment []int8, signatureFragment Trytes) Trits {
	k := NewKerl()
	for i := 0; i < 27; i++ {
		bb := signatureFragment[i*HashSize/3 : (i+1)*HashSize/3].Trits()
		for j := normalizedBundleFragment[i] + 13; j > 0; j-- {
			kerl := NewKerl()
			kerl.Absorb(bb)
			bb, _ = kerl.Squeeze(HashSize)
		}
		k.Absorb(bb)
	}
	tr, _ := k.Squeeze(HashSize)
	return tr
}


// IsValidSig validates signatureFragment.
func IsValidSig(address Address, signatureFragments []Trytes, bundleHash Trytes) bool {
	byteKey, err := Trytes(address[:81]).Trits().Bytes()
	if err != nil {
		log.Fatalf("Error converting from trytes %s\n", err)
	}

	pkKey, err := eckey.NewCompressedPublicKey(byteKey[:33])

	uncompPk, err := pkKey.Uncompress()
	if err != nil {
		log.Fatal(err)
	}

	for i := range signatureFragments {
		rebuilt, err := TrytesToAscii(signatureFragments[i])
		if err != nil {
			log.Fatal(err)
		}
		rebSig := new(schnorr.Signature)
		copy(rebSig[:], base58.Decode(rebuilt))
		fmt.Printf("Sig2 is %x\n", rebSig)
		sha256.New()
		hash := sha256.Sum256([]byte(bundleHash))
		err = schnorr.Verify(rebSig, uncompPk, hash[:]); if err != nil {
			log.Fatalf("The error is: %s\nThe hash is %s and the public key is %s", err, bundleHash, uncompPk.Compress())
		}
	}


	if err != nil {
		return false
	}

	return true
}

// Address represents address without a checksum for iota.
// Don't type cast, use ToAddress instead to check validity.
type Address Trytes

// Error types for address
var (
	ErrInvalidAddressTrytes = errors.New("addresses without checksum are 81 trytes in length")
	ErrInvalidAddressTrits  = errors.New("addresses without checksum are 243 trits in length")
)


// ToAddress converts string to address, and checks the validity
func ToAddress(t string) (Address, error) {
	return Trytes(t).ToAddress()
}

// CreateAddress creates a new address - this method is to allow for exporting to java
func (a *Address) CreateAddress(seed Trytes, index int) Address {
	addr, err := NewAddress(seed, index)
	if err != nil {
		log.Fatal(err)
	}
	return addr
}

// ToAddress convert trytes(with and without checksum) to address and checks the validity
func (t Trytes) ToAddress() (Address, error) {
	if len(t) == 90 {
		t = t[:81]
	}

	a := Address(t)
	err := a.IsValid()
	if err != nil {
		return "", err
	}

	if len(t) == 90 {
		cs := a.Checksum()
		if t[81:] != cs {
			return "", errors.New("checksum is illegal")
		}
	}

	return a, nil
}

// IsValid return nil if address is valid.
func (a Address) IsValid() error {
	if !(len(a) == 81) {
		return ErrInvalidAddressTrytes
	}

	return Trytes(a).IsValid()
}

// Checksum returns checksum trytes. This panics if len(address)<81
// TODO: does this really need to panic? can it just return an error?
func (a Address) Checksum() Trytes {
	if len(a) != 81 {
		panic("len(address) must be 81")
	}
	return a.Hash()[81-9 : 81]
}

// Hash hashes the address and returns trytes
func (a Address) Hash() Trytes {
	k := NewKerl()
	t := Trytes(a).Trits()
	k.Absorb(t)
	h, _ := k.Squeeze(HashSize)
	return h.Trytes()
}

// WithChecksum returns Address+checksum. This panics if len(address)<81
// TODO: does this really need to panic?
func (a Address) WithChecksum() Trytes {
	if len(a) != 81 {
		panic("len(address) must be 81")
	}

	cu := a.Checksum()
	return Trytes(a) + cu
}
