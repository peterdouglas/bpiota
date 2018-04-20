package giota

import (
	"github.com/peterdouglas/bp-go"
	"math/big"
	"github.com/NebulousLabs/hdkey/eckey"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"errors"
	"crypto/aes"
	"github.com/ethereum/go-ethereum/common/math"
	"io"
	"crypto/rand"
	"crypto/cipher"
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

	pkCompressed, err := eckey.NewPublicKeyCoords(c.Vector.X, c.Vector.Y)
	if err != nil {
		return "", err
	}
	pkInt := new(big.Int).SetBytes(pkCompressed.Compress()[:])
	keyTrit := make([]byte, 48)
	copy(keyTrit, pkInt.Bytes())
	trits, err := BytesToTrits(keyTrit)
	if err != nil {
		return "", err
	}
	c.Trytes = trits.Trytes()
	return c.Trytes, nil

}

func (c *Commitment) Decode() (ECPoint, error) {
	byteKey, err := c.Trytes.Trits().Bytes()
	if err != nil {
		return ECPoint{}, err
	}

	pkKey, err := eckey.NewCompressedPublicKey(byteKey[:33])

	uncompPk, err := pkKey.Uncompress()
	if err != nil {
		return ECPoint{}, err
	}
	x, y := uncompPk.Coords()
	return ECPoint{x, y}, nil
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
	block, err := aes.NewCipher(gamma.Bytes())
	if err != nil {
		return err
	}

	encVal := math.PaddedBigBytes(v, aes.BlockSize)

	if len(encVal)%aes.BlockSize != 0 {
		return errors.New("Encrypted value is not a multiple of the blocksize")
	}

	ciphertext := make([]byte, aes.BlockSize+len(encVal))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], encVal)


	c.EncValue = ciphertext
	return nil
}



func (p *ProofPrep) GenerateRangeProof(gamma *big.Int) (bp_go.RangeProof, []*big.Int) {
	valArr := make([]*big.Int, len(*p))
	commitArr := make([]bp_go.ECPoint, len(*p))
	totalEC := bp_go.EC.Zero()
	total := int64(0)

	for i, proof := range *p {
		valArr[i] = proof.value
		bpEC := bp_go.ECPoint{X: proof.commitment.Vector.X, Y: proof.commitment.Vector.Y}
		commitArr[i] = bpEC
		totalEC.Add(bpEC)
		total += proof.value.Int64()
	}
	if !totalEC.Equal(bp_go.EC.Zero()) {
		errors.New("The total sum was not equal to zero")
	}

	rp := bp_go.RPProveTrans(gamma, big.NewInt(total))

	return rp, valArr
}
