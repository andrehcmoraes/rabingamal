// Package rabingamal combines the asymmetric algorithms Rabin and ElGamal.
package rabingamal

import (
	"math/big"
	"math/rand"
	"testing"
	"time"
)

// Test costants, usually small for faster results.
const (
	TestBitSize = 512
	MaxPrimes   = 1
)

func TestRabinElGamal(t *testing.T) {
	pub, prv := RabGamNewKeyPair(TestBitSize)

	// Test specific cases.
	cases := []int64{
		0, 1, 2,
	}
	for _, v := range cases {
		m := big.NewInt(v)
		c := RabGamWrap(m, pub)
		got := RabGamUnwrap(c, prv)
		if got.Cmp(m) != 0 {
			t.Errorf("RabinGamal failed on specific tests.\nGot:%q\nWant:%q\n", got.String(), m.String())
		}
	}

	// Naive, random tests.
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := int64(0); i < 50; i++ {
		m := big.NewInt(0)
		m.Rand(r, pub.gam.q)

		c := RabGamWrap(m, pub)
		got := RabGamUnwrap(c, prv)
		if got.Cmp(m) != 0 {
			t.Errorf("RabinGamal failed.\nGot:%q\nWant:%q\n", got.String(), m.String())
		}
	}

}
