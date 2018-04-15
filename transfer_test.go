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
	"testing"
)

var (
	seed             Trytes
	skipTransferTest = false
)

func init() {
	ts := "CLBHL9DOQXUHBWORNBHNPUB9JQUHYLLXXCJQRJVRJXYHAAISJPTDA9ZFVLPPNAHLDNMDDMGYXEDVROMQV"
	if ts == "" {
		skipTransferTest = true
		return
	}

	s, err := ToTrytes(ts)
	if err != nil {
		skipTransferTest = true
	} else {
		seed = s
	}
}

func TestTransfer1(t *testing.T) {
	if skipTransferTest {
		t.Skip("transfer test skipped because a valid $TRANSFER_TEST_SEED was not specified")
	}

	var (
		err  error
		adr  Address
		adrs []Address
	)

	for i := 0; i < 5; i++ {
		api := NewAPI(RandomNode(), nil)
		adr, adrs, err = GetUsedAddress(api, seed)
		if err == nil {
			break
		}
	}

	if err != nil {
		t.Error(err)
	}

	t.Log(adr, adrs)
	if len(adrs) < 1 {
		t.Error("GetUsedAddress is incorrect")
	}

	var bal Balances
	for i := 0; i < 5; i++ {
		api := NewAPI(RandomNode(), nil)
		bal, err = GetInputs(api, seed, 0, 10, 1000)
		if err == nil {
			break
		}
	}

	if err != nil {
		t.Error(err)
	}

	t.Log(bal)
	if len(bal) < 1 {
		t.Error("GetInputs is incorrect")
	}
}

// nolint: gocyclo
func TestTransfer2(t *testing.T) {
	if skipTransferTest {
		t.Skip("transfer test skipped because a valid $TRANSFER_TEST_SEED was not specified")
	}

	var err error
	trs := []Transfer{
		Transfer{
			Address: "BXHANKTHPJUPUVZOLJPZPQLDZPWVSBPGLMLSOYFZM9RSHVZRRBZJZJDZYTNRHXBVMQKFT9DVKVNDPCGC9ZXXTZCTMB",
			Value:   20,
			Tag:     "MOUDAMEPO",
		},
	}

	var bdl Bundle
	for i := 0; i < 5; i++ {
		api := NewAPI(RandomNode(), nil)
		bdl, err = PrepareTransfers(api, seed, trs, nil, "")
		if err == nil {
			break
		}
	}

	if err != nil {
		t.Error(err)
	}

	if len(bdl) < 3 {
		for _, tx := range bdl {
			t.Log(tx.Trytes())
		}
		t.Fatal("PrepareTransfers is incorrect len(bdl)=", len(bdl))
	}

	if err = bdl.IsValid(); err != nil {
		t.Error(err)
	}

	name, pow := GetBestPoW()
	t.Log("using PoW: ", name)

	for i := 0; i < 5; i++ {
		api := NewAPI(RandomNode(), nil)
		bdl, err = Send(api, seed, trs, DefaultMinWeightMagnitude, pow)
		if err == nil {
			break
		}
	}

	if err != nil {
		t.Error(err)
	}

	for _, tx := range bdl {
		t.Log(tx.Trytes())
	}
}
