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
	"math"
	"time"
	"github.com/NebulousLabs/hdkey"
	"log"
	"github.com/NebulousLabs/hdkey/schnorr"
	"github.com/decred/base58"
	"crypto/sha256"
	"math/big"
	"github.com/peterdouglas/bp-go"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"sync"
)

// (3^27-1)/2
const maxTimestampTrytes = "MMMMMMMMM"

// Number of random walks to perform. Currently IRI defaults to a range of 5 to 27
const DefaultNumberOfWalks = 5

var waitGroup sync.WaitGroup

// GetUsedAddress generates a new address which is not found in the tangle
// and returns its new address and used addresses.
func GetUsedAddress(api *API, seed Trytes) (Address, []Address, error) {
	var all []Address
	for index := 0; ; index++ {
		adr, err := NewAddress(seed, index)
		if err != nil {
			return "", nil, err
		}

		r := FindTransactionsRequest{
			Addresses: []Address{adr},
		}

		resp, err := api.FindTransactions(&r)
		if err != nil {
			return "", nil, err
		}

		if len(resp.Hashes) == 0 {
			return adr, all, nil
		}

		// reached the end of the loop, so must be used address, repeat until return
		all = append(all, adr)
	}
}

// GetInputs gets all possible inputs of a seed and returns them with the total balance.
// end must be under start+500.
func GetInputs(api *API, seed Trytes, start, end int, threshold int64) (Balances, error) {
	var err error
	var adrs []Address

	if start > end || end > (start+500) {
		return nil, errors.New("Invalid start/end provided")
	}

	switch {
	case end > 0:
		adrs, err = NewAddresses(seed, start, end-start)
	default:
		_, adrs, err = GetUsedAddress(api, seed)
	}

	if err != nil {
		return nil, err
	}

	return api.Balances(adrs, seed)
}

// Transfer is the  data to be transfered by bundles.
type Transfer struct {
	Address Address
	Value   int64
	Message Trytes
	Tag     Trytes
}

const sigSize = SignatureMessageFragmentTrinarySize / 3

func addOutputs(secInt *big.Int, receiverPub *secp256k1.PublicKey, preProof *ProofPrep, trs []Transfer) (Bundle, []Trytes) {
	var (
		bundle Bundle
		frags  []Trytes
	)
	for _, tr := range trs {
		nsigs := 1

		// If message longer than 2187 trytes, increase signatureMessageLength (add 2nd transaction)
		switch {
		case len(tr.Message) > sigSize:
			// Get total length, message / maxLength (2187 trytes)
			n := int(math.Floor(float64(len(tr.Message)) / sigSize))
			nsigs += n

			// While there is still a message, copy it
			for k := 0; k < n; k++ {
				var fragment Trytes
				switch {
				case k == n-1:
					fragment = tr.Message[k*sigSize:]
				default:
					fragment = tr.Message[k*sigSize : (k+1)*sigSize]
				}

				// Pad remainder of fragment
				frags = append(frags, fragment)
			}
		default:
			frags = append(frags, tr.Message)
		}

		// Add first entries to the bundle
		// Slice the address in case the user provided a checksummed one

		// generate the commitment to add to the bundle
		val := big.NewInt(tr.Value)
		comm := GenerateCommitment(receiverPub, secInt, val)

		tempPre := PreProof{
			commitment: comm,
			receiver:   &tr.Address,
			sender:     nil,
			value:      val,
		}


		rp := bp_go.RPProveTrans(comm.Blind, val)
		serRP, _ := rp.Serialize()
		bundle.Add(nsigs, tr.Address, comm, time.Now(), serRP, tr.Tag)

		*preProof = append(*preProof, tempPre)



	}
	return bundle, frags
}

// AddressInfo includes an address and its infomation for signing.
type AddressInfo struct {
	Seed     Trytes
	Sk       *hdkey.HDKey
	Index    int
}

// Address makes an Address from an AddressInfo
func (a *AddressInfo) Address() (Address, error) {
	pkCompressed := a.Sk.PublicKey().Compress()
	pkInt := new(big.Int).SetBytes(pkCompressed[:])
	keyTrit := make([]byte, 48)
	copy(keyTrit, pkInt.Bytes())
	trits, err := BytesToTrits(keyTrit)
	if err != nil {
		return "", err
	}

	return trits.Trytes().ToAddress()

}

// Key makes a Key from an AddressInfo
func (a *AddressInfo) Key() (Trytes, error) {
	return NewPublicKey(a.Seed, a.Index)
}

// Key makes a Key from an AddressInfo
func (a *AddressInfo) Secret() (error){
	sk, err := NewSecKey(a.Seed, a.Index)
	a.Sk = sk
	if err != nil {
		return err
	}

	return nil
}

func setupInputs(api *API, seed Trytes, inputs []AddressInfo, total int64) (Balances, []AddressInfo, error) {
	var bals Balances
	var err error

	switch {
	case inputs == nil:
		//  Case 2: Get inputs deterministically
		//  If no inputs provided, derive the addresses from the seed and
		//  confirm that the inputs exceed the threshold

		// If inputs with enough balance
		bals, err = GetInputs(api, seed, 0, 100, 100)
		if err != nil {
			return nil, nil, err
		}

		inputs = make([]AddressInfo, len(bals))
		for i := range bals {
			inputs[i].Index = bals[i].Index
			inputs[i].Seed = seed
			inputs[i].Secret()
		}
	default:
		//  Case 1: user provided inputs
		adrs := make([]Address, len(inputs))
		for i, ai := range inputs {
			adrs[i], err = ai.Address()

			if err != nil {
				return nil, nil, err
			}
		}

		//  Validate the inputs by calling getBalances (in call to Balances)
		bals, err = api.Balances(adrs, seed)

	}

	// Return not enough balance error
	if total > bals.Total() {
		return nil, nil, errors.New("Not enough balance")
	}
	return bals, inputs, nil
}

// PrepareTransfers gets an array of transfer objects as input, and then prepares
// the transfer by generating the correct bundle as well as choosing and signing the
// inputs if necessary (if it's a value transfer).
func PrepareTransfers(api *API, seed Trytes, trs []Transfer, inputs []AddressInfo, remainder Address) (Bundle, error) {
	var err error
	// TODO - change to be dynamic to allow smaller or larger sigs
	var total int64 = 0

	// Calculate the total here as we need it for the inputs
	for _, t := range trs {
		total += t.Value
	}

	// Get inputs if we are sending tokens
	// If no input required, don't sign and simply finalize the bundle
	bals, inputs, err := setupInputs(api, seed, inputs, total)
	if err != nil {
		return nil, err
	}

	// Create the private key that will be used to sign and commit
	err = inputs[0].Secret()
	senderKey, err := inputs[0].Sk.SecretKey()
	if err != nil {
		return nil, err
	}
	senderSec, _ := secp256k1.PrivKeyFromBytes(senderKey[:])

	// Generate the shared secret nonce to allow the receiver to verify the entire transaction
	pubKey, err := trs[0].Address.DecodePubKey()
	if err != nil {
		return nil, err
	}
	receiverPub := secp256k1.NewPublicKey(pubKey.Coords())
	// Generate the shared secret for this address
	sharedSec := secp256k1.GenerateSharedSecret(senderSec, receiverPub)
	secInt := new(big.Int)
	secInt.SetBytes(sharedSec)

	var preProof ProofPrep
	bundle, frags := addOutputs(secInt, receiverPub, &preProof, trs)


	if total <= 0 {
		bundle.Finalize(frags)
		return bundle, nil
	}


	err = addRemainder(receiverPub, secInt, &preProof, api, bals, &bundle, remainder, seed, total)
	if err != nil {
		return nil, err
	}

	bundle.Finalize(frags)
	err = signInputs(&preProof, inputs, bundle, seed)
	return bundle, err
}

func GenerateCommitment(receiverPub *secp256k1.PublicKey, secInt *big.Int, value *big.Int) *Commitment {
	comm := new(Commitment)

	comm.Generate(receiverPub, value, secInt)
	return comm
}

func addRemainder(receiverPub *secp256k1.PublicKey, secInt *big.Int, preProof *ProofPrep, api *API, in Balances, bundle *Bundle, remainder Address, seed Trytes, total int64) error {
	for _, bal := range in {
		var err error
		val := big.NewInt(-bal.Value)
		// generate the commitment for the remainder

		comm := GenerateCommitment(receiverPub, secInt, val)
		addr, err := bal.Address.Address()
		tempProof := PreProof{
			commitment: comm,
			receiver:   &addr,
			sender:     nil,
			value:      val,
		}

		*preProof = append(*preProof, tempProof)

		// Add input as bundle entry
		bundle.Add(1, addr, comm, time.Now(), "", EmptyHash)

		// If there is a remainder value add extra output to send remaining funds to
		if remain := bal.Value - total; remain > 0 {
			// If user has provided remainder address use it to send remaining funds to
			adr := remainder
			if adr == "" {
				// Generate a new Address by calling getNewAddress
				adr, _, err = GetUsedAddress(api, seed)
				if err != nil {
					return err
				}
			}
			pubkey, err := adr.DecodePubKey()

			if err != nil {
				return err
			}
			val := big.NewInt(remain)
			// generate the commitment for the remainder
			comm := GenerateCommitment(secp256k1.NewPublicKey(pubkey.Coords()), secInt, val)


			tempProof := PreProof{
				commitment: comm,
				receiver:   &adr,
				sender:     nil,
				value:      val,
			}

			*preProof = append(*preProof, tempProof)

			rp := bp_go.RPProveTrans(comm.Blind, val)

			serRP, _ := rp.Serialize()

			// Remainder bundle entry
			bundle.Add(1, adr, comm, time.Now(), serRP, EmptyHash)
			return nil
		}

		// If multiple inputs provided, subtract the totalTransferValue by
		// the inputs balance
		if total -= bal.Value; total == 0 {
			return nil
		}
	}
	return nil
}

func signInputs(preProofs *ProofPrep, inputs []AddressInfo, bundle Bundle, seed Trytes) error {
	//  Get the normalized bundle hash
	nHash := bundle.Hash()

	sha256.New()
	hash := sha256.Sum256([]byte(nHash))
	valArr := preProofs.GetVals()

	// SIGNING OF INPUTS
	// Here we do the actual signing of the inputs. Iterate over all bundle transactions,
	// find the inputs, get the corresponding private key, and calculate signatureFragment
	for i, bd := range bundle {
		if valArr[i].Sign()  <= 0 {
			continue
		}

		// Get the corresponding keyIndex and security of the address
		var ai AddressInfo
		for _, in := range inputs {
			adr, err := in.Address()
			if err != nil {
				return err
			}

			if adr == bd.Address {
				ai = in
				break
			}
		}

		// Get corresponding private key of the address
		ai.Seed = seed
		err := ai.Secret()

		if err != nil {
			log.Fatal(err)
		}
		sk, err := ai.Sk.SecretKey()

		if err != nil {
			log.Fatal(err)
		}
		sig, err := schnorr.Sign(sk, hash[:])
		if err != nil {
			log.Fatal("The signature has failed")
		}
		tryteSig, err := AsciiToTrytes(base58.Encode(sig[:]))

		// Calculate the new signatureFragment with the first bundle fragment
		bundle[i].SignatureMessageFragment = pad(tryteSig, sigSize)

	}
	return nil
}

func doPow(tra *GetTransactionsToApproveResponse, depth int64, trytes []Transaction, mwm int64, pow PowFunc) error {
	var prev Trytes
	var err error
	for i := len(trytes) - 1; i >= 0; i-- {
		switch {
		case i == len(trytes)-1:
			trytes[i].TrunkTransaction = tra.TrunkTransaction
			trytes[i].BranchTransaction = tra.BranchTransaction
		default:
			trytes[i].TrunkTransaction = prev
			trytes[i].BranchTransaction = tra.TrunkTransaction
		}

		timestamp := Int2Trits(time.Now().UnixNano()/1000000, TimestampTrinarySize).Trytes()
		trytes[i].AttachmentTimestamp = timestamp
		trytes[i].AttachmentTimestampLowerBound = ""
		trytes[i].AttachmentTimestampUpperBound = maxTimestampTrytes

		trytes[i].Nonce, err = pow(trytes[i].Trytes(), int(mwm))
		if err != nil {
			return err
		}

		prev = trytes[i].Hash()
	}
	return nil
}

// SendTrytes does attachToTangle and finally, it broadcasts the transactions.
func SendTrytes(api *API, depth int64, trytes []Transaction, mwm int64, pow PowFunc) error {
	tra, err := api.GetTransactionsToApprove(depth, DefaultNumberOfWalks, "")
	if err != nil {
		return err
	}

	switch {
	case pow == nil:
		at := AttachToTangleRequest{
			TrunkTransaction:   tra.TrunkTransaction,
			BranchTransaction:  tra.BranchTransaction,
			MinWeightMagnitude: mwm,
			Trytes:             trytes,
		}

		// attach to tangle - do pow
		attached, err := api.AttachToTangle(&at)
		if err != nil {
			return err
		}

		trytes = attached.Trytes
	default:
		err := doPow(tra, depth, trytes, mwm, pow)
		if err != nil {
			return err
		}
	}

	// Broadcast and store tx
	err = api.StoreTransactions(trytes)
	if err != nil {
		return err
	}
	return api.BroadcastTransactions(trytes)
}

// Promote sends transanction using tail as reference (promotes the tail transaction)
func Promote(api *API, tail Trytes, depth int64, trytes []Transaction, mwm int64, pow PowFunc) error {
	if len(trytes) == 0 {
		return errors.New("empty transfer")
	}
	resp, err := api.CheckConsistency([]Trytes{tail})
	if err != nil {
		return err
	} else if !resp.State {
		return errors.New(resp.Info)
	}

	tra, err := api.GetTransactionsToApprove(depth, DefaultNumberOfWalks, tail)
	if err != nil {
		return err
	}

	switch {
	case pow == nil:
		at := AttachToTangleRequest{
			TrunkTransaction:   tra.TrunkTransaction,
			BranchTransaction:  tra.BranchTransaction,
			MinWeightMagnitude: mwm,
			Trytes:             trytes,
		}

		// attach to tangle - do pow
		attached, err := api.AttachToTangle(&at)
		if err != nil {
			return err
		}

		trytes = attached.Trytes
	default:
		err := doPow(tra, depth, trytes, mwm, pow)
		if err != nil {
			return err
		}
	}

	// Broadcast and store tx
	return api.BroadcastTransactions(trytes)
}

// Send sends tokens. If you need to do pow locally, you must specifiy pow func,
// otherwise this calls the AttachToTangle API
func Send(api *API, seed Trytes, trs []Transfer, mwm int64, pow PowFunc) (Bundle, error) {
	bd, err := PrepareTransfers(api, seed, trs, nil, "")
	if err != nil {
		return nil, err
	}

	err = SendTrytes(api, Depth, []Transaction(bd), mwm, pow)
	return bd, err
}
