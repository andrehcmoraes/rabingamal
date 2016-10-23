// Package rabingamal combines the asymmetric algorithms Rabin and ElGamal.
package rabingamal

// File rabingamal.go implements the Rabin-ElGamal cryptosystem union.

import (
	"math/big"
)

// RabGamPublicKey holds the public key used in RabinGamalWrap.
type RabGamPublicKey struct {
	rab *RabinPublicKey
	gam *ElGamalPublicKey
	siz int
}

// RabGamPrivateKey holds the private key used in RabinGamalUnwrap.
type RabGamPrivateKey struct {
	rab *RabinPrivateKey
	gam *ElGamalPrivateKey
	siz int
}

// RabGamNewKeyPair outputs a new RabinGamalKeyPair with given bitSize.
func RabGamNewKeyPair(bitSize int64) (*RabGamPublicKey, *RabGamPrivateKey) {
	pubRab, prvRab := RabinNewKeyPair(2 * bitSize)
	pubGam, prvGam := ElGamalNewKeyPair(bitSize)

	// Number of bytes required to store a number up to 2^(2*bitSize).
	l := int(bitSize / 4)

	return &RabGamPublicKey{rab: pubRab, gam: pubGam, siz: l},
		&RabGamPrivateKey{rab: prvRab, gam: prvGam, siz: l}
}

// RabGamWrap wraps a plaintext 'm' with a given RabinGamal public key 'k'.
func RabGamWrap(m *big.Int, k *RabGamPublicKey) *big.Int {
	// Wrap with ElGamal.
	c1, c2 := ElGamalWrap(m, k.gam)

	b1 := leadZeroes(c1.Bytes(), k.siz)
	b2 := leadZeroes(c2.Bytes(), k.siz)

	// b = HIGH(c1) || HIGH(c2) || LOW(c1) || LOW(c2)
	var b []byte
	l := k.siz / 2
	b = append(b, b1[:l]...)
	b = append(b, b2[:l]...)
	b = append(b, b1[l:]...)
	b = append(b, b2[l:]...)

	c := big.NewInt(0)
	c.SetBytes(b)

	// Wrap with Rabin.
	return RabinWrap(c, k.rab)
}

// RabGamUnwrap unwraps a cryptotext 'c' with a given private key 'k'.
func RabGamUnwrap(c *big.Int, k *RabGamPrivateKey) *big.Int {
	// Unwrap with Rabin.
	x := RabinUnwrap(c, k.rab)
	b := leadZeroes(x.Bytes(), 2*k.siz)

	// Recover c1 and c2.
	l := k.siz / 2
	b1, b2 := make([]byte, 0), make([]byte, 0)
	b1 = append(b1, b[:l]...)
	b2 = append(b2, b[l:2*l]...)
	b1 = append(b1, b[2*l:3*l]...)
	b2 = append(b2, b[3*l:]...)

	c1, c2 := big.NewInt(0), big.NewInt(0)
	c1.SetBytes(b1)
	c2.SetBytes(b2)

	// Unwrap with ElGamal.
	return ElGamalUnwrap(c1, c2, k.gam)
}
