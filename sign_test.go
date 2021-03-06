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
	"testing"
)


func TestNewAddressFromTrytes(t *testing.T) {
	tests := []struct {
		name          string
		address       Trytes
		validAddr     bool
		checksum      Trytes
		validChecksum bool
	}{
		{
			name:          "valid address and checksium",
			address:       "RGVOWCDJAGSO9TNLBBPUVYE9KHBOAZNVFRVKVYYCHRKQRKRNKGGWBF9WCRJVROKLVKWZUMBABVJGAALWU",
			validAddr:     true,
			checksum:      "NPJ9QIHFW",
			validChecksum: true,
		},
		{
			name:          "test blank address fails",
			address:       "",
			validAddr:     false,
			checksum:      "",
			validChecksum: true,
		},
		{
			name:          "valid address and checksum",
			address:       "999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
			validAddr:     true,
			checksum:      "A9BEONKZW",
			validChecksum: true,
		},
		{
			name:          "valid address with invalid checksum",
			address:       "RGVOWCDJAGSO9TNLBBPUVYE9KHBOAZNVFRVKVYYCHRKQRKRNKGGWBF9WCRJVROKLVKWZUMBABVJGAALWU",
			validAddr:     true,
			checksum:      "A9BEONKZW",
			validChecksum: false,
		},
	}

	for _, tt := range tests {
		adr, err := tt.address.ToAddress()
		switch {
		case (err != nil) == tt.validAddr:
			t.Fatalf("%s: NewAddressFromTrytes(%q) expected (err != nil) to be %#v\nerr: %#v",
				tt.name, tt.address, tt.validAddr, err)
		case (err == nil && adr.Checksum() != tt.checksum) == tt.validChecksum:
			t.Fatalf("NewAddressFromTrytes(%q) checksum mismatch\nwant: %s\nhave: %s",
				tt.address, tt.checksum, adr.Checksum())
		case !tt.validAddr || !tt.validChecksum:
			continue
		}

		wcs := adr.WithChecksum()
		if wcs != Trytes(adr)+adr.Checksum() {
			t.Error("WithChecksum is incorrect")
		}

		adr2, err := ToAddress(string(tt.address))
		if err != nil {
			t.Error(err)
		}

		if adr != adr2 {
			t.Error("ToAddress is incorrect")
		}
	}
}

func TestAddress(t *testing.T) {
	tests := []struct {
		name         Trytes
		seed         Trytes
		seedIndex    int
		seedSecurity int
		address      Trytes
		addressValid bool
	}{
		{
			name:         "test valid address 1",
			seed:         "CLBHL9DOQXUHBWORNBHNPUB9JQUHYLLXXCJQRJVRJXYHAAISJPTDA9ZFVLPPNAHLDNMDDMGYXEDVROMQV",
			seedIndex:    0,
			seedSecurity: 2,
			address:      "UYUNFEZOOIMJJOMBXZTSRK9BNXVDCLEJFTZTJVHYPNUFG9HDXGRSIEIJDGXIGAMJOQMHJATQXLCSUKAD9",
		},
		{
			name:         "test valid address 2",
			seed:         "CLBHL9DOQXUHBWORNBHNPUB9JQUHYLLXXCJQRJVRJXYHAAISJPTDA9ZFVLPPNAHLDNMDDMGYXEDVROMQV",
			seedIndex:    1,
			address:      "FQLSSVMTIPCTRAR9JERPEAYUOHZAYHHEJPJEFXPWBDNVJJAJGKXOCLJKUMHUTPKBFMIIHWHUBXFUSXGD9",
		},
	}

	for _, tt := range tests {
		address, err := NewAddress(tt.seed, tt.seedIndex)
		if err != nil {
			t.Errorf("%s: NewAddress failed with error: %s", tt.name, err)
		}

		addressCheck, err := tt.address.ToAddress()
		if err != nil {
			t.Errorf("%s: ToAddress failed with err: %s", tt.name, err)
		}

		if address != addressCheck {
			t.Errorf("%s: address: %s != address: %s", tt.name, address, addressCheck)
		}

		err = address.IsValid()
		if err != nil {
			t.Errorf("%s: address failed to validate: %s", tt.name, err)
		}
	}
}

func TestSeed(t *testing.T) {
	for i := 0; i < 10000; i++ {
		s1 := NewSeed()
		if err := s1.IsValid(); err != nil {
			t.Error("NewSeed is not valid")
		}

		s2 := NewSeed()
		if err := s2.IsValid(); err != nil {
			t.Error("NewSeed is not valid")
		}

		if s1 == s2 {
			t.Error("NewSeed is incorrect")
		}
	}
}
