// Package rabingamal combines the asymmetric algorithms Rabin and ElGamal.
package rabingamal

import (
	"math/big"
	"math/rand"
	"time"
)

func GenerateNewKeyPair() (q, g, h, x *big.Int) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	// q is a prime and the order of the group G.
	q = NewPrime()
	z := big.NewInt(0)
	z.Sub(q, bigOne)

	// Message space is the group G
	// G is cyclic and all elements except the identity are generators.
	g = big.NewInt(0)
	g.Rand(r, z)
	g.Add(g, bigOne)

	// Pick random element x.
	x = big.NewInt(0)
	x.Rand(r, z)
	x.Add(x, bigOne)

	// h = g^x mod q
	h = big.NewInt(0)
	h.Exp(g, x, q)

	return q, g, h, x
}

func Wrap(m, q, g, h *big.Int) (c1, c2 *big.Int) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	c1 = big.NewInt(0)
	c2 = big.NewInt(0)

	z := big.NewInt(0)
	z.Sub(q, bigOne)

	// Pick random element y.
	y := big.NewInt(0)
	y.Rand(r, z)
	y.Add(y, bigOne)

	// c1 = g^y mod q
	c1.Exp(g, y, q)

	// c2 = m * (h^y) mod q
	c2.Exp(h, y, q)
	c2.Mul(c2, m)

	return c1, c2
}

func Unwrap(c1, c2, q, x *big.Int) (m *big.Int) {
	m = big.NewInt(0)
	s := big.NewInt(0)

	// s = c1 ^ x mod q
	s.Exp(c1, x, q)

	// p = s^(-1) mod q
	p := invMod(s, q)

	// Recover m.
	m.Mul(c2, p)
	m.Mod(m, q)

	return m
}
