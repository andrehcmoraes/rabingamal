// Package rabingamal combines the asymmetric algorithms Rabin and ElGamal.
package rabingamal

import (
	"math/big"
	"math/rand"
	"testing"
	"time"
)

func TestElGamal(t *testing.T) {
	// Random tests.
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for k := 0; k < 5; k++ {
		pub, prv := ElGamalNewKeyPair(TestBitSize)

		for i := int64(0); i < 100; i++ {
			m := big.NewInt(0)
			m.Rand(r, pub.q)

			c1, c2 := ElGamalWrap(m, pub)
			got := ElGamalUnwrap(c1, c2, prv)

			if got.Cmp(m) != 0 {
				t.Errorf("ElGamal failed.\nGot:%q\nWant:%q\n", got.String(), m.String())
			}
		}
	}

}
