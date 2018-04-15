package giota

import (
	"testing"
	bp"github.com/peterdouglas/bp-go"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"math/big"
	"fmt"
)

func TestBP(t *testing.T) {
	bp.EC = bp.NewECPrimeGroupKey(128)
	// create the private keys
	aliceSK, _ := secp256k1.GeneratePrivateKey()
	bobSK, _ := secp256k1.GeneratePrivateKey()

	// gen public keys
	alicePkx, alicePky := aliceSK.Public()
	bobPkx, bobPky := bobSK.Public()

	valArr := make([]*big.Int, 4)
	valArr[0] = big.NewInt(1000000000)
	valArr[1] = big.NewInt(7)
	valArr[2] = big.NewInt(4)
	valArr[3] = big.NewInt(0)

	alicePk := secp256k1.NewPublicKey(alicePkx, alicePky)
	bobPk := secp256k1.NewPublicKey(bobPkx, bobPky)
	mrp, commitments := bp.PrepareTransaction(aliceSK, bobPk, alicePk, valArr)
	strMP, err := mrp.Serialize()
	//tryteEncr := base58.Encode(commitments[0].EncValue)
	tryte, err := AsciiToTrytes(strMP)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("%+v\n", tryte)
	if bp.MRPVerify(mrp, commitments) {
		fmt.Println("Range Proof Verification works")
	} else {
		t.Error("*****Range Proof FAILURE")
	}

}
