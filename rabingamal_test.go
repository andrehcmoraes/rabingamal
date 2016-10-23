// Package rabingamal combines the asymmetric algorithms Rabin and ElGamal.
package rabingamal

import (
	"math/big"
	"math/rand"
	"testing"
	"time"
)

const (
	TestBitSize = 128
)

func TestRabinElGamal(t *testing.T) {
	return
	pub, prv := RabinGamalNewKeyPair(TestBitSize)

	// Test specific cases
	cases := []int64 {
		0, 1, 2,
	}
	for _, v := range cases {
		m := big.NewInt(v)
		c := RabinGamalWrap(m, pub)
		got := RabinGamalUnwrap(c, prv)
		if got.Cmp(m) != 0 {
			t.Errorf("RabinGamal failed.\nGot:%q\nWant:%q\n", got.String(), m.String())
		}
	}

	// Random tests.

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for k := 0; k < 5; k++ {
		pub, prv = RabinGamalNewKeyPair(TestBitSize)

		for i := int64(0); i < 100; i++ {
			m := big.NewInt(0)
			m.Rand(r, pub.gam.q)

			c := RabinGamalWrap(m, pub)
			got := RabinGamalUnwrap(c, prv)
			if got.Cmp(m) != 0 {
				t.Errorf("RabinGamal failed.\nGot:%q\nWant:%q\n", got.String(), m.String())
			}
		}
	}


}
