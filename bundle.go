/*
MIT License

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
	"errors"
	"fmt"
	"time"
	"github.com/peterdouglas/bp-go"
	"github.com/decred/base58"
	"github.com/NebulousLabs/hdkey/eckey"
)

func pad(orig Trytes, size int) Trytes {
	out := make([]byte, size)
	copy(out, []byte(orig))

	for i := len(orig); i < size; i++ {
		out[i] = '9'
	}
 	return Trytes(out)
}

// Bundle is transactions that are bundled (grouped) together when creating a transfer.
type Bundle []Transaction

// Add adds a bundle to bundle slice. Elements which are not specified are filled with
// zeroed trits.
func (bs *Bundle) Add(num int, address Address, value *Commitment, timestamp time.Time, tag Trytes) error {
	if tag == "" {
		tag = EmptyHash[:27]
	}
	v, err := value.Encode()
	if err != nil {
		return err
	}

	blind, err := AsciiToTrytes(base58.Encode(value.EncValue))

	for i := 0; i < num; i++ {
		val := Trytes("")
		if (i == 0) {
			val = v
		}

		b := Transaction{
			SignatureMessageFragment:      emptySig,
			Address:                       address,
			Value:                         pad(val, ValueTrinarySize/3),
			BlindingFactor:                pad(blind, BlindingTrinarySize/3),
			RangeProof:                    pad(emptySig, RangeProofTrinarySize/3),
			ObsoleteTag:                   pad(tag, TagTrinarySize/3),
			Timestamp:                     timestamp,
			CurrentIndex:                  int64(len(*bs) - 1),
			LastIndex:                     0,
			Bundle:                        EmptyHash,
			TrunkTransaction:              EmptyHash,
			BranchTransaction:             EmptyHash,
			Tag:                           pad(tag, TagTrinarySize/3),
			AttachmentTimestampLowerBound: EmptyHash,
			AttachmentTimestampUpperBound: EmptyHash,
			Nonce: EmptyHash,
		}
		*bs = append(*bs, b)
	}
	return nil
}

// Finalize filled sigs, bundlehash, and indices elements in bundle.
func (bs Bundle) Finalize(sig []Trytes) {
	h := bs.getValidHash()

	for i := range bs {
		if len(sig) > i && sig[i] != "" {
			bs[i].SignatureMessageFragment = pad(sig[i], SignatureMessageFragmentTrinarySize/3)
		}

		bs[i].CurrentIndex = int64(i)
		bs[i].LastIndex = int64(len(bs) - 1)
		bs[i].Bundle = h
	}
}

// Hash calculates hash of Bundle.
func (bs Bundle) Hash() Trytes {
	k := NewKerl()
	buf := make(Trits, 243+243*3)

	for i, b := range bs {
		getTritsToHash(buf, &b, i, len(bs))
		k.Absorb(buf)
	}

	h, _ := k.Squeeze(HashSize)
	return h.Trytes()
}

// getValidHash calculates hash of Bundle and increases ObsoleteTag value
// until normalized hash doesn't have any 13
func (bs Bundle) getValidHash() Trytes {
	k := NewKerl()
	hashedLen := BundleTrinaryOffset - AddressTrinaryOffset

	buf := make(Trits, hashedLen*len(bs))
	for i, b := range bs {
		getTritsToHash(buf[i*hashedLen:], &b, i, len(bs))
	}
	var i = 0
	for {
		k.Absorb(buf)
		hashTrits, _ := k.Squeeze(HashSize)
		h := hashTrits.Trytes()
		n := h.Normalize()
		valid := true

		for _, v := range n {
			if v == 13 {
				valid = false
				break
			}
		}

		offset := ObsoleteTagTrinaryOffset - AddressTrinaryOffset

		if valid {
			bs[0].ObsoleteTag = buf[offset : offset+ObsoleteTagTrinarySize].Trytes()
			fmt.Printf("Valid, i = %s", i)
			return h
		}
		i++
		k.Reset()
		incTrits(buf[offset : offset+ObsoleteTagTrinarySize])

	}
}

func getTritsToHash(buf Trits, b *Transaction, i, l int) {
	copy(buf, Trytes(b.Address).Trits())
	copy(buf[AddressTrinarySize:],b.Value.Trits())
	copy(buf[AddressTrinarySize+ValueTrinarySize:], b.ObsoleteTag.Trits())
	copy(buf[AddressTrinarySize+ValueTrinarySize+ObsoleteTagTrinarySize:], Int2Trits(b.Timestamp.Unix(), TimestampTrinarySize))
	copy(buf[AddressTrinarySize+ValueTrinarySize+ObsoleteTagTrinarySize+TimestampTrinarySize:], Int2Trits(int64(i), CurrentIndexTrinarySize))   //CurrentIndex
	copy(buf[AddressTrinarySize+ValueTrinarySize+ObsoleteTagTrinarySize+TimestampTrinarySize+CurrentIndexTrinarySize:], Int2Trits(int64(l-1), LastIndexTrinarySize)) //LastIndex
}

// Categorize categorizes a list of transfers into sent and received. It is important to
// note that zero value transfers (which for example, are being used for storing
// addresses in the Tangle), are seen as received in this function.
func (bs Bundle) Categorize(adr Address) (send Bundle, received Bundle) {
	send = make(Bundle, 0, len(bs))
	received = make(Bundle, 0, len(bs))

	for _, b := range bs {
		switch {
		case b.Address != adr:
			continue
		case b.RangeProof[0:6] != "9999999999999999":
			received = append(received, b)
		default:
			send = append(send, b)
		}
	}
	return
}

// IsValid checks the validity of Bundle.
// It checks that total balance==0 and that its has a valid signature.
// The caller must call Finalize() beforehand.
// nolint: gocyclo
func (bs Bundle) IsValid() error {
	var total int64
	sigs := make(map[Address][]Trytes)
	proofValid := false
	commitments := make([]bp_go.ECPoint, len(bs))
	totalEC := bp_go.EC.Zero()

	for i, b := range bs {
		byteKey, err := Trytes(b.Value).Trits().Bytes()
		if err != nil {
			return err
		}
		eckey.NewPublicKey(byteKey)
		pkKey, err := eckey.NewCompressedPublicKey(byteKey[:33])
		uncom, err := pkKey.Uncompress()
		x, y := uncom.Coords()
		commitments[i] = bp_go.ECPoint{
			X: x,
			Y: y,
		}

		totalEC.Add(commitments[i])
		if err != nil {
			return err
		}
	}
	if !totalEC.Equal(bp_go.EC.Zero()) {
		errors.New("The commitments did not add up to zero")
	}

	for index, b := range bs {

		switch {
		case b.CurrentIndex != int64(index):
			return fmt.Errorf("CurrentIndex of index %d is not correct", b.CurrentIndex)
		case b.LastIndex != int64(len(bs)-1):
			return fmt.Errorf("LastIndex of index %d is not correct", b.CurrentIndex)
		case b.RangeProof[0:6] != "9999999999999999":
			continue
		}

		sigs[b.Address] = append(sigs[b.Address], b.SignatureMessageFragment)

		/* Removing long signature functionality for now
		// Find the subsequent txs with the remaining signature fragment
		for i := index; i < len(bs)-1; i++ {
			tx := bs[i+1]

			// Check if new tx is part of the signature fragment
			if tx.Address == b.Address && tx.Value == 0 {
				sigs[tx.Address] = append(sigs[tx.Address], tx.SignatureMessageFragment)
			}
		}*/
		if !proofValid {
			proof, err := TrytesToAscii(b.RangeProof)
			if err != nil {
				return err
			}
			rangeProof := new(bp_go.MultiRangeProof)
			err = rangeProof.Rebuild(proof)
			if err != nil {
				return err
			}
			valid := bp_go.MRPVerify(rangeProof, commitments)
			if !valid {
				err := errors.New("The range proof failed to verify")
				return err
			}
		}
	}

	// Validate the signatures
	h := bs.Hash()
	for adr, sig := range sigs {

		if !IsValidSig(adr, sig, h) {
			return errors.New("invalid signature")
		}
	}

	if total != 0 {
		return errors.New("total balance of Bundle is not 0")
	}

	return nil
}
