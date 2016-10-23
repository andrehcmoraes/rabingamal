// Package rabingamal combines the asymmetric algorithms Rabin and ElGamal.
package rabingamal

import (
	"testing"
	"math/big"
	"math/rand"
	"time"
)

func TestElGamal(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for k := 0; k < 5; k++ {
		q, g, h, x := GenerateNewKeyPair()

		// Iterative tests.
		for i := int64(0); i < 100; i++ {
			m := big.NewInt(0)
			m.Rand(r, q)
			c1, c2 := Wrap(m, q, g, h)
			got := Unwrap(c1, c2, q, x)

			if got.Cmp(m) != 0 {
				t.Errorf("ElGamal failed.\nGot:%q\nWant:%q\n", got.String(), m.String())
			}
		}
	}

}
