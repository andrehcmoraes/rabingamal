// Package rabingamal combines the asymmetric algorithms Rabin and ElGamal.
package rabingamal

import (
	"math/big"
	"math/rand"
	"testing"
	"time"
)

const (
	TestBitSize = 512
	MaxPrimes = 1
)

func TestRabinElGamal(t *testing.T) {
	pub, prv := RabinGamalNewKeyPair(TestBitSize)
	max := big.NewInt(TestBitSize)
	max.Div(max, bigFour)
	max.Exp(bigTwo, max, nil)

	// Test specific cases
	cases := []int64 {
		0, 1, 2,
	}
	for _, v := range cases {
		m := big.NewInt(v)
		c := RabinGamalWrap(m, pub)
		got := RabinGamalUnwrap(c, prv)
		if got.Cmp(m) != 0 {
			t.Errorf("RabinGamal failed on specific tests.\nGot:%q\nWant:%q\n", got.String(), m.String())
		}
	}

	// Random tests.
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := int64(0); i < 50; i++ {
		m := big.NewInt(0)
		m.Rand(r, max)

		c := RabinGamalWrap(m, pub)
		got := RabinGamalUnwrap(c, prv)
		if got.Cmp(m) != 0 {
			t.Errorf("RabinGamal failed.\nGot:%q\nWant:%q\n", got.String(), m.String())
		}
	}

}
