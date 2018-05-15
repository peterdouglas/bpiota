package giota

import (
	"github.com/peterdouglas/bp-go"
	"math/big"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"errors"
	"github.com/decred/base58"
	"fmt"
)

type PreProof struct {
	commitment *Commitment
	receiver *Address
	sender *Address
	value *big.Int
}

type ProofPrep []PreProof

type ECPoint struct {
	X *big.Int
	Y *big.Int
}

type Commitment struct {
	Vector ECPoint
	EncValue []byte
	Blind *big.Int
	sSecret *big.Int
	Trytes Trytes

}

func (c *Commitment) Encode() (Trytes, error) {

	pkCompressed := secp256k1.NewPublicKey(c.Vector.X, c.Vector.Y)
	//baseTr, err := AsciiToTrytes(base58.Encode(pkCompressed.SerializeCompressed()))
	//if err != nil {
	//	return "", err
	//}
	//fmt.Printf("Base trytes are: %+v\n", base58.Encode(pkCompressed.SerializeCompressed()))
	keyTrit := make([]byte, 48)
	copy(keyTrit,pkCompressed.SerializeCompressed())
	trits, err := BytesToTrits(keyTrit)
	if err != nil {
		return "", err
	}
	c.Trytes = trits.Trytes()
	//byte2 := c.Trytes.Trits().JavaTrits()
	fmt.Printf("Trytes: %+v\n", c.Trytes)
	//c.Trytes = baseTr
	return c.Trytes, nil

}

func (c *Commitment) Decode() (ECPoint, error) {
	for i := len(c.Trytes)-1; i > 0 ; i--  {
		if string(c.Trytes)[i] != '9' {
			c.Trytes = c.Trytes[:i+1]
			break
		}
	}

	asciKey, err := TrytesToAscii(c.Trytes)
	if err != nil {
		return ECPoint{}, err
	}
	byteKey := base58.Decode(asciKey)
	pkKey, err := secp256k1.ParsePubKey(byteKey[:33])

	return ECPoint{pkKey.GetX(), pkKey.GetY()}, nil
}

// Generate a single commitment from a commitment struct
func (c *Commitment) Generate(receiverKey *secp256k1.PublicKey, v, gamma *big.Int)  error {

	if v.Sign() < 0 {
		c.Vector = ECPoint(bp_go.EC.G.Mult(v).Add(bp_go.EC.H.Mult(gamma)).Neg())
	} else {
		c.Vector = ECPoint(bp_go.EC.G.Mult(v).Add(bp_go.EC.H.Mult(gamma)))

	}
	c.Blind = gamma
	// now we encrypt the value so the receiver can recreate the trans
	ciphertext, err := secp256k1.Encrypt(receiverKey, v.Bytes())
	if err != nil {
		return err
	}

	c.EncValue = ciphertext
	return nil
}

func (p *ProofPrep) GetVals() ([]*big.Int) {
	valArr := make([]*big.Int, len(*p))
	blindArr := make([]*big.Int, len(*p))
	commitArr := make([]bp_go.ECPoint, len(*p))
	totalEC := bp_go.EC.Zero()
	total := int64(0)

	for i, proof := range *p {
		valArr[i] = proof.value
		blindArr[i] = proof.commitment.Blind
		bpEC := bp_go.ECPoint{X: proof.commitment.Vector.X, Y: proof.commitment.Vector.Y}
		commitArr[i] = bpEC
		totalEC.Add(bpEC)
		total += proof.value.Int64()
	}
	if !totalEC.Equal(bp_go.EC.Zero()) {
		errors.New("The total sum was not equal to zero")
	}


	return valArr
}
