// Package rabingamal combines the asymmetric algorithms Rabin and ElGamal.
package rabingamal

import (
	"math/big"
	"math/rand"
	"testing"
	"time"
)

func TestRabin(t *testing.T) {
	pub, prv := RabinNewKeyPair(TestBitSize)

	// Test specific cases
	cases := []int64 {
		1, 2,
	}
	for _, v := range cases {
		m := big.NewInt(v)

		c := RabinWrap(m, pub)
		got := RabinUnwrap(c, prv)
		if got.Cmp(m) != 0 {
			t.Errorf("Rabin failed.\nGot:%q\nWant:%q\n", got.String(), m.String())
		}
	}

	// Random tests.
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := int64(0); i < 100; i++ {
		m := big.NewInt(0)
		m.Rand(r, prv.q)

		c := RabinWrap(m, pub)
		got := RabinUnwrap(c, prv)

		if got.Cmp(m) != 0 {
			t.Errorf("Rabin failed.\nGot:%q\nWant:%q\n", got.String(), m.String())
		}
	}
}
