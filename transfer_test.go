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
	"fmt"
)

var (
	seed             Trytes
	skipTransferTest = false
)

func init() {
	ts := "CLBHL9DOQXUHBWORNBHNPUB9JQUHYLLXXCJQRJVRJXYHAAISJPTDA9ZFVLPPNAHLDNMDDMGYXEDVROMQV"
	//ts := "CIXIFADSMGPA9HERAVAZMCUSEDJHKDKVYIEZNCAIYJQNHZNSHUEDSREQYIIMIQLTRPKPAFTAJX9FNNZBK"
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
			Value:   1000000,
			Tag:     "MOUDAMEPA",
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

	if len(bdl) < 2 {
		for _, tx := range bdl {
			t.Log(tx.Trytes())
		}
		t.Fatal("PrepareTransfers is incorrect len(bdl)=", len(bdl))
	}

	//spew.Dump(bdl)
	if err = bdl.IsValid(); err != nil {
		t.Error(err)
	}

	name, _ := GetBestPoW()
	t.Log("using PoW: ", name)

	for i := 0; i < 5; i++ {
		api := NewAPI(RandomNode(), nil)
		bdl, err = Send(api, seed, trs, DefaultMinWeightMagnitude, nil)
		if err == nil {
			break
		} else {
			fmt.Println(err)
		}
	}

	if err != nil {
		t.Error(err)
	}

	for _, tx := range bdl {
		t.Log(tx.Trytes())
	}
}

func TestBundleRange(t *testing.T) {
	if skipTransferTest {
		t.Skip("transfer test skipped because a valid $TRANSFER_TEST_SEED was not specified")
	}

	var err error
	trs := []Transfer{
		Transfer{
			Address: "BXHANKTHPJUPUVZOLJPZPQLDZPWVSBPGLMLSOYFZM9RSHVZRRBZJZJDZYTNRHXBVMQKFT9DVKVNDPCGC9ZXXTZCTMB",
			Value:   1500000,
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
	fmt.Printf("%v\n", bdl[0].Trytes())

	//spew.Dump(bdl)
	if err = bdl.IsValid(); err != nil {
		t.Error(err)
	}

}

func TestConvertToTrytes(t *testing.T) {
	strRP := "65nEV9yjLkxHQaKULWuhaTTxmCk883LkToPXgtnNfuPu8ogcnZunNzYzjRw5pizj3v2xCjm77KEzqxR26bhnrA2MyotW9mUPrwWCTGpqeq3yqawxtNguFCv9VbhgPiVnfzApT1reRTUgVhT1LFpsPGUKDNKCayBwadpvpU5vYhWi7Y1pVLA1dMJi4LzRTotqzU6EdcKuvzS6aqcsMSWPFzzsvwMRowzwmL94cykKdXt4qfVb3L61eXe8htb8icwptz6jvXX5xHtk7sxiU2FhnSHCoVxJpcxE6WWQ3UdYfJsc1rUiYZEgBRTMZr5PweUAJFLcbUDFJ5wE81GdxnSLw86QsPZ4s72g3psLHzaWVLg7S8jwjHnNrbwHMH3eB7TPsPZkU7uYHEH8A611emYeoM4LkoFcTk352heXrVFhd7A3APwMuEhhAw6HfPDwmXqcY916m9nRtTBMRdy9fe3vQrm8fdFUWXKWSqroqbaJLETsXnhkmk7bvv4B7Jeb9V61cX4M3C8e2Na8zTiLpbCNBPTJjU9bLXNwmTCf7nPeDr2a1Cm6SM9uTnPcZNweXw3EswJZQAjtBXjfqk9jcr2YTGACKZGFmJEBowAtqC8shrhSJgnvP8EXmXcjsKF4qoNpiUhks5dzJZizt1vc5eDLkh8btmF9v99XJStMEzpBQByg1Xp12izXUxyceu35V7PKxzw1Zx8jabBTyTv8iHjpQ3xMEGt6onUgCtqugxax2qrpKKQ18sZjeQ7oRGWjWw4YTGCPY4ESoUKjf8wh9iJDeQjHEKK9YwcVwzcSygSjP1dXbm491NxgnWEgz5BAu264izvbHnNR3Yvkwn6ktRkACCYCBEURfVyKWkoPRuYRb9fvmfCyWRBXkaNnLRQVDkHa8fubEnMXnb4SVm6nd3h27i3jK5bjaxcGML3Vc1iygh9bM1iswJGDdg5hXHeDmq1GsDqnA2Ws4bgX8vgJMP1vZAX679fvDVbeBAYhDndnK7M82uubCbY4pnhuRb95DWj5xPkDhT3UhCjaZTsWhUjweZuwkxfpRsn8DjgNQSgvMixUdi78Wd2N1YS86SbVchG8tykfzP1cyt6dxBPBVCXbWZMQXS3xxA4VxTgdNUSWiMV2AThVYuB7bisRBwcHKutEZa5ULvt518d58rzh8E4LXUNPnEov4q2xQYDrnTaZ5f6EEZTVoBQ84uvuWfsy1zukzRjKhpoPm2N6G2r6rNft7nc4GPyfPNfevj1neC7cJ2txEaairLMr9e3sgGzjSWZSA5EtkHnVo85oEY29qdsfemk8hQ5iPGxPfbpchzVoJqiExqRygcC1YiXUpHgvMeHrxrRAAKcoZ2y67Vtp5vrT7BdXEqyauJidmNZPbdFxQ9P7HNGZEZxGiDoYxEGLHxbAqAEExzLYxmkzWciRMV8zgVZ4vTANZV93rcYb6hd9J3BmxMW7mqpFvZhBEj83CQYK7BpdZvugUw2rzWFoGXKEQKA41DUTahunPAfHz"
	trRp,err := AsciiToTrytes(strRP)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("The tryte length is %s\n", len(trRp))

}

func TestApproveTransactions(t *testing.T) {
    api := NewAPI(RandomNode(), nil)
    trs := []Transfer{
        Transfer{
            Address: "BXHANKTHPJUPUVZOLJPZPQLDZPWVSBPGLMLSOYFZM9RSHVZRRBZJZJDZYTNRHXBVMQKFT9DVKVNDPCGC9ZXXTZCTMB",
            Value:   150000000000,
            Tag:     "MOUDAMEPO",
        },}
    var transArr []Transaction
    for i := 0; i < 20; i++ {
        addr, err := NewAddress(seed, i+5)
        trs[0].Address = addr
        bdl, err := Send(api, seed, trs, DefaultMinWeightMagnitude, nil)
        if err != nil {
            t.Error(err)
        }
        transArr = append(transArr, bdl...)
    }

    for i:=0; i < 3; i++ {
        err := api.BroadcastTransactions(transArr)
        if err != nil {
            t.Error(err)
        }
    }
}