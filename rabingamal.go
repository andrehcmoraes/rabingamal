// Package rabingamal combines the asymmetric algorithms Rabin and ElGamal.
package rabingamal

import (
	"math/big"
)

type RabinGamalPublicKey struct {
	rab *RabinPublicKey
	gam *ElGamalPublicKey
	siz int
}

type RabinGamalPrivateKey struct {
	rab *RabinPrivateKey
	gam *ElGamalPrivateKey
	siz int
}

func RabinGamalNewKeyPair(bitSize int64) (*RabinGamalPublicKey, *RabinGamalPrivateKey) {
	pubRab, prvRab := RabinNewKeyPair(2*bitSize)
	pubGam, prvGam := ElGamalNewKeyPair(bitSize)

	size := big.NewInt(bitSize)
	size.Exp(bigTwo, size, nil)
	l := len(size.Bytes())

	return &RabinGamalPublicKey{rab:pubRab, gam:pubGam, siz:l},
		&RabinGamalPrivateKey{rab:prvRab, gam:prvGam, siz:l}
}

func RabinGamalWrap(m *big.Int, pub *RabinGamalPublicKey) *big.Int {
	c1, c2 := ElGamalWrap(m, pub.gam)

	b1 := c1.Bytes()
	l1 := pub.siz - len(b1)
	if l1 > 1 {
		z := make([]byte, l1)
		for i := range z {
			z[i] = 0
		}
		b1 = append(z, b1 ... )
	}

	b2 := c2.Bytes()
	l2 := pub.siz - len(b2)
	if l2 > 1 {
		z := make([]byte, l2)
		for i := range z {
			z[i] = 0
		}
		b2 = append(z, b2 ... )
	}
	b := append(b1, b2 ... )

	c := big.NewInt(0)
	c.SetBytes(b)

	return RabinWrap(c, pub.rab)
}

func RabinGamalUnwrap(c *big.Int, prv *RabinGamalPrivateKey) *big.Int {
	x := RabinUnwrap(c, prv.rab)
	b := x.Bytes()
	b1, b2 := b[:prv.siz - 1], b[prv.siz - 1:]

	c1, c2 := big.NewInt(0), big.NewInt(0)
	c1.SetBytes(b1)
	c2.SetBytes(b2)

	return ElGamalUnwrap(c1, c2, prv.gam)
}
