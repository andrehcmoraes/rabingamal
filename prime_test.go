// Package rabingamal combines the asymmetric algorithms Rabin and ElGamal.
package rabingamal

import (
	"testing"
	"math/big"
	"math/rand"
	"time"
)

func TestMillerRabin(t *testing.T) {
	// Test specific cases
	cases := []struct {
		in int64
		want bool
	}{
		{0, false},
		{1, false},
		{2, true},
		{3, true},
		{4, false},
		{5, true},
	}
	for _, c := range cases {
		out := millerRabin(big.NewInt(c.in), 0)
		if out != c.want {
			t.Errorf("MillerRabin(%q) == %q, want %q", c.in, out, c.want)
		}
	}

	// Random tests, compare with Golang's official MillerRabin test.
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	n := big.NewInt(0)

	for i := 0; i < 10000; i++ {
		// Get new random.
		n.Rand(r, bigSize)
		want := n.ProbablyPrime(10)
		got := millerRabin(n, 10)

		if got != want {
			t.Errorf("Random test failed MillerRabin, got %v, want %v.\nNumber:%q",
				got, want, n.String())
		}
	}

}
