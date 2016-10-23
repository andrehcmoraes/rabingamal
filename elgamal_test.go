// Package rabingamal combines the asymmetric algorithms Rabin and ElGamal.
package rabingamal

import (
	"testing"
	"math/big"
)

func TestElGamal(t *testing.T) {

	for k := 0; k < 5; k++ {
		q, g, h, x := GenerateNewKeyPair()

		// Iterative tests.
		for i := int64(2); i < 100; i++ {
			m := big.NewInt(i)
			c1, c2 := Wrap(m, q, g, h)
			got := Unwrap(c1, c2, q, x)

			if got.Cmp(m) != 0 {
				t.Errorf("ElGamal failed.\nGot:%q\nWant:%q\n", got.String(), m.String())
			}
		}
	}

}
