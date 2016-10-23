// Package rabingamal combines the asymmetric algorithms Rabin and ElGamal.
package rabingamal

import (
	"bytes"
	"math/big"
)

const (
	LastBytes = 8
)

type RabinPrivateKey struct {
	n, p, q *big.Int
}

type RabinPublicKey struct {
	n *big.Int
}

func RabinNewKeyPair(bitSize int64) (*RabinPublicKey, *RabinPrivateKey) {
	p := NewPrime(bitSize)
	q := NewPrime(bitSize)
	n := big.NewInt(0)

	n.Mul(p, q)

	return &RabinPublicKey{n:big.NewInt(0).Set(n)},
		&RabinPrivateKey{n:n, p:p, q:q}
}

func RabinWrap(m *big.Int, pub *RabinPublicKey) (*big.Int) {
	c := big.NewInt(0)

	// Add leading zeros bytes until we have at least 64 bits.
	b := m.Bytes()
	l := LastBytes - len(b)
	if l > 0 {
		z := make([]byte, l)
		for i := range z {
			z[i] = 0
		}
		b = append(z, b ... )
	}

	// Repeat last 64 bits.
	l = len(b) - LastBytes
	b = append(b, b[:LastBytes] ... )
	c.SetBytes(b)

	c.Exp(c, bigTwo, pub.n)
	return c
}

func RabinUnwrap(c *big.Int, prv *RabinPrivateKey) (*big.Int) {
	xp, xq := big.NewInt(0), big.NewInt(0)
	yp, yq := big.NewInt(0), big.NewInt(0)
	mp, mq := big.NewInt(0), big.NewInt(0)
	r, s := big.NewInt(0), big.NewInt(0)
	m := big.NewInt(0)

	xp.Add(prv.p, bigOne)
	xq.Add(prv.q, bigOne)

	xp.Div(xp, bigFour)
	xq.Div(xq, bigFour)

	mp.Exp(c, xp, prv.p)
	mq.Exp(c, xq, prv.q)

	_, yp, yq = euclides(prv.p, prv.q)

	mq.Mul(mq, yp)
	mq.Mul(mq, prv.p)

	mp.Mul(mp, yq)
	mp.Mul(mp, prv.q)

	r.Add(mq, mp)
	r.Mod(r, prv.n)

	s.Sub(mq, mp)
	s.Mod(s, prv.n)

	// All four roots.
	roots := [](*big.Int){
		big.NewInt(0).Set(r),
		big.NewInt(0).Sub(prv.n, r),
		big.NewInt(0).Set(s),
		big.NewInt(0).Sub(prv.n, s),
	}

	// Find the correct root.
	for _, root := range roots {
		b := root.Bytes()
		l := 2*LastBytes - len(b)
		// Add leading zeroes.
		if l > 0 {
			z := make([]byte, l)
			for i := range z {
				z[i] = 0
			}
			b = append(z, b ... )
		}
		repeat := len(b) - LastBytes
		if bytes.Equal(b[:LastBytes], b[repeat:]) {
			b = b[:repeat]
			m.SetBytes(b)
			return m
		}
	}

	// Should not happen with valid messages.
	panic("Rabin failed!")
}
