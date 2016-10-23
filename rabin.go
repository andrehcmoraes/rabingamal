// Package rabingamal combines the asymmetric algorithms Rabin and ElGamal.
package rabingamal

import (
	"bytes"
	"math/big"
)

const (
	LastBytes = 8
)

func GenerateNewKey() (n, p, q *big.Int) {
	p = NewPrime()
	q = NewPrime()
	n = big.NewInt(0)

	n.Mul(p, q)

	return n, p, q
}

func rabinWrap(m, n *big.Int) (c *big.Int) {
	c = big.NewInt(0)

	// Add random bytes until we have at least 64 bits.
	b := m.Bytes()
	for len(b) < LastBytes + 1 {
		b = append(b, byte(0x0))
	}

	// Repeat last 64 bits.
	l := len(b) - LastBytes
	b = append(b, b[l:] ... )
	c.SetBytes(b)

	c.Exp(c, bigTwo, n)
	return c
}

func rabinUnwrap(c, n, p, q *big.Int) (m *big.Int) {
	xp, xq := big.NewInt(0), big.NewInt(0)
	yp, yq := big.NewInt(0), big.NewInt(0)
	mp, mq := big.NewInt(0), big.NewInt(0)
	r, s := big.NewInt(0), big.NewInt(0)
	m = big.NewInt(0)

	xp.Add(p, bigOne)
	xq.Add(q, bigOne)

	xp.Div(xp, bigFour)
	xq.Div(xq, bigFour)

	mp.Exp(c, xp, p)
	mq.Exp(c, xq, q)

	_, yp, yq = euclides(p, q)

	mq.Mul(mq, yp)
	mq.Mul(mq, p)

	mp.Mul(mp, yq)
	mp.Mul(mp, q)

	r.Add(mq, mp)
	r.Mod(r, n)

	s.Sub(mq, mp)
	s.Mod(s, n)

	// All four roots.
	roots := [](*big.Int){
		big.NewInt(0).Set(r),
		big.NewInt(0).Sub(n, r),
		big.NewInt(0).Set(s),
		big.NewInt(0).Sub(n, s),
	}

	// Find the correct root.
	for _, root := range roots {
		b := root.Bytes()
		last := len(b) - 2*LastBytes
		repeat := last + LastBytes
		if bytes.Equal(b[last:repeat], b[repeat:]) {
			b = b[:repeat]
			if len(b) == LastBytes + 1 {
				b = b[:len(b) - LastBytes]
			}
			m.SetBytes(b)
			return m
		}
	}

	return nil
}
