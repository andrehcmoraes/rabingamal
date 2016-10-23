// Package rabingamal combines the asymmetric algorithms Rabin and ElGamal.
package rabingamal

// File elgamal.go implements the ElGamal cryptosystem.

import (
	"math/big"
	"math/rand"
	"time"
)

// ElGamalPublicKey holds the public key used in ElGamalWrap.
type ElGamalPublicKey struct {
	q, g, h *big.Int
}

// ElGamalPrivateKey holds the private key used in ElGamalUnwrap.
type ElGamalPrivateKey struct {
	q, x *big.Int
}

// ElGamalNewKeyPair outputs a new ElGamalKeyPair with given bitSize.
func ElGamalNewKeyPair(bitSize int64) (*ElGamalPublicKey, *ElGamalPrivateKey) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	// q is a prime and the order of the group G.
	q := NewPrime(bitSize)
	z := big.NewInt(0)
	z.Sub(q, bigOne)

	// Message space is the group G
	// G is cyclic and all elements except the identity are generators.
	// Pick random generator g.
	g := big.NewInt(0)
	g.Rand(r, z)
	g.Add(g, bigOne)

	// Pick random element x.
	x := big.NewInt(0)
	x.Rand(r, z)
	x.Add(x, bigOne)

	// h = g^x mod q.
	h := big.NewInt(0)
	h.Exp(g, x, q)

	return &ElGamalPublicKey{q: q, g: g, h: h},
		&ElGamalPrivateKey{q: big.NewInt(0).Set(q), x: big.NewInt(0).Set(x)}
}

// ElGamalWrap wraps a plaintext 'm' with a given ElGamal public key 'k'.
func ElGamalWrap(m *big.Int, k *ElGamalPublicKey) (*big.Int, *big.Int) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	c1 := big.NewInt(0)
	c2 := big.NewInt(0)

	z := big.NewInt(0)
	z.Sub(k.q, bigOne)

	// Pick random element y.
	y := big.NewInt(0)
	y.Rand(r, z)
	y.Add(y, bigOne)

	// c1 = g^y mod q
	c1.Exp(k.g, y, k.q)

	// c2 = m * (h^y) mod q
	c2.Exp(k.h, y, k.q)
	c2.Mul(c2, m)

	return c1, c2
}

// ElGamalUnwrap unwraps a cryptotext 'c' with a given Rabin private key 'k'.
func ElGamalUnwrap(c1, c2 *big.Int, k *ElGamalPrivateKey) *big.Int {
	m := big.NewInt(0)
	s := big.NewInt(0)

	// s = c1 ^ x mod q
	s.Exp(c1, k.x, k.q)

	// p = s^(-1) mod q
	p := invMod(s, k.q)

	// Recover m.
	m.Mul(c2, p)
	return m.Mod(m, k.q)
}
