// Package rabingamal combines the asymmetric algorithms Rabin and ElGamal.
package rabingamal

// File rabin.go implements the Rabin cryptosystem.

import (
	"bytes"
	"math/big"
)

const (
	// LastBytes defines how many bytes should be repeated.
	LastBytes = 8
)

// RabinPublicKey holds the public key used in RabinWrap.
type RabinPublicKey struct {
	n *big.Int
}

// RabinPrivateKey holds the private key used in RabinUnwrap.
type RabinPrivateKey struct {
	n, p, q, yp, yq *big.Int
}

// RabinNewKeyPair outputs a new RabinKeyPair with given bitSize.
func RabinNewKeyPair(bitSize int64) (*RabinPublicKey, *RabinPrivateKey) {
	p := NewPrime(bitSize)
	q := NewPrime(bitSize)
	n := big.NewInt(0)

	// n = p * q, the public key.
	n.Mul(p, q)

	// Pre-compute yp and yq
	_, yp, yq := xGCD(p, q)

	return &RabinPublicKey{n: big.NewInt(0).Set(n)},
		&RabinPrivateKey{n: n, p: p, q: q, yp: yp, yq: yq}
}

// RabinWrap wraps a plaintext 'm' with a given Rabin public key 'k'.
func RabinWrap(m *big.Int, k *RabinPublicKey) *big.Int {
	c := big.NewInt(0)

	// Add leading zeros bytes until we have at least 64 bits.
	c.Mod(m, k.n)
	b := leadZeroes(c.Bytes(), LastBytes)

	// Repeat last 64 bits.
	b = append(b, b[:LastBytes]...)
	c.SetBytes(b)
	if c.Cmp(k.n) > 0 {
		panic("Rabin KeyPair is too small to handle this message.")
	}

	// c^2 mod n is the ciphertext.
	return c.Exp(c, bigTwo, k.n)
}

// RabinUnwrap unwraps a cryptotext 'c' with a given Rabin private key 'k'.
func RabinUnwrap(c *big.Int, k *RabinPrivateKey) *big.Int {
	r, s := big.NewInt(0), big.NewInt(0)
	m := big.NewInt(0)

	// Modulus square root.
	mp, mq := modSquareRoot(c, k.p), modSquareRoot(c, k.q)

	// Find the roots.
	mq.Mul(mq, k.yp)
	mq.Mul(mq, k.p)

	mp.Mul(mp, k.yq)
	mp.Mul(mp, k.q)

	r.Add(mq, mp)
	r.Mod(r, k.n)

	s.Sub(mq, mp)
	s.Mod(s, k.n)

	// All four roots.
	roots := [](*big.Int){
		big.NewInt(0).Set(r),
		big.NewInt(0).Sub(k.n, r),
		big.NewInt(0).Set(s),
		big.NewInt(0).Sub(k.n, s),
	}

	// Find the correct root.
	for _, root := range roots {
		// Add leading zeroes.
		b := leadZeroes(root.Bytes(), 2*LastBytes)
		repeat := len(b) - LastBytes
		// Should only happen on the correct root.
		if bytes.Equal(b[:LastBytes], b[repeat:]) {
			b = b[:repeat]
			return m.SetBytes(b)
		}
	}

	// Should not happen with valid messages.
	panic("Rabin failed!")
}
