// Package rabingamal combines the asymmetric algorithms Rabin and ElGamal.
package rabingamal

import (
	"testing"
	"math/big"
)

func TestRabin(t *testing.T) {
	for k := 0; k < 1; k++ {
		n, p, q := GenerateNewKey()

		// Iterative tests.
		for i := int64(2); i < 5; i++ {
			m := big.NewInt(i)
			c := rabinWrap(m, n)
			got := rabinUnwrap(c, n, p, q)

			if got.Cmp(m) != 0 {
				t.Errorf("Rabin failed.\nGot:%q\nWant:%q\n", got.String(), m.String())
			}
		}
	}
}
