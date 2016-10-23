// Package rabingamal combines the asymmetric algorithms Rabin and ElGamal.
package rabingamal

import (
	"math/big"
	"math/rand"
	"testing"
	"time"
)

func TestInvMod(t *testing.T) {
	m := NewPrime(int64(TestBitSize))

	for i := 0; i < MaxPrimes; i++ {
		a := NewPrime(int64(TestBitSize))
		if a.Cmp(m) > 0 {
			z := big.NewInt(0)
			z.Set(m)
			m.Set(a)
			a.Set(z)
		}
		want := big.NewInt(0)
		want.ModInverse(a, m)
		got := invMod(a, m)
		if got.Cmp(want) != 0 {
			t.Errorf("invMod failed.\na=%s\nm=%s\ngot=%s\nwant=%s", a.String(), m.String(),
				got.String(), want.String())
		}
	}
}

func TestNewPrime(t *testing.T) {
	for i := 0; i < MaxPrimes; i++ {
		n := NewPrime(int64(TestBitSize))
		if !n.ProbablyPrime(10) {
				t.Errorf("NewPrime generated a composite number %s", n.String())
		}
	}
}

func TestQualityNumber(t *testing.T) {
	// Test specific cases
	cases := []struct {
		in int64
		want bool
	}{
		{0, false},
		{1, false},
		{TestBitSize/2, true},
	}
	for _, c := range cases {
		z := big.NewInt(c.in)
		z.Exp(bigTwo, z, nil)
		out := qualityNumber(z, big.NewInt(int64(TestBitSize)))
		if out != c.want {
			t.Errorf("qualityNumber(2^%s) == %v, want %v", c.in, out, c.want)
		}
	}
}

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
		out := millerRabin(big.NewInt(c.in), 10)
		if out != c.want {
			t.Errorf("millerRabin(%q) == %q, want %q", c.in, out, c.want)
		}
	}

	// Random tests, compare with Golang's official MillerRabin test.
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	n := big.NewInt(0)
	max := big.NewInt(0)
	bigSize := big.NewInt(int64(TestBitSize))

	max.Exp(bigTwo, bigSize, nil)

	for i := 0; i < 100; i++ {
		// Get new random.
		n.Rand(r, max)
		want := n.ProbablyPrime(10)
		got := millerRabin(n, 10)

		if got != want {
			t.Errorf("Random test failed millerRabin, got %v, want %v.\nNumber:%q",
				got, want, n.String())
		}
	}

}
