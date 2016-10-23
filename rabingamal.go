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

	size := big.NewInt(2*bitSize)
	size.Exp(bigTwo, size, nil)
	l := len(size.Bytes())
	l = l - l % 2

	return &RabinGamalPublicKey{rab:pubRab, gam:pubGam, siz:l},
		&RabinGamalPrivateKey{rab:prvRab, gam:prvGam, siz:l}
}

func RabinGamalWrap(m *big.Int, pub *RabinGamalPublicKey) *big.Int {
	c1, c2 := ElGamalWrap(m, pub.gam)

	b1 := c1.Bytes()
	b2 := c2.Bytes()

	l1 := pub.siz - len(b1)
	l2 := pub.siz - len(b2)

	if l1 > 0 {
		z := make([]byte, l1)
		for i := range z {
			z[i] = 0
		}
		b1 = append(z, b1 ... )
	}

	if l2 > 0 {
		z := make([]byte, l2)
		for i := range z {
			z[i] = 0
		}
		b2 = append(z, b2 ... )
	}

	b := make([]byte, 0)
	b = append(b, b1[:pub.siz/2] ... )
	b = append(b, b2[:pub.siz/2] ... )
	b = append(b, b1[pub.siz/2:] ... )
	b = append(b, b2[pub.siz/2:] ... )

	c := big.NewInt(0)
	c.SetBytes(b)

	return RabinWrap(c, pub.rab)
}

func RabinGamalUnwrap(c *big.Int, prv *RabinGamalPrivateKey) *big.Int {
	x := RabinUnwrap(c, prv.rab)
	b := x.Bytes()

	l := 2*prv.siz - len(b)
	if l > 0 {
		z := make([]byte, l)
		for i := range z {
			z[i] = 0
		}
		b = append(z, b ... )
	}

	l = prv.siz/2
	b1, b2 := make([]byte, 0), make([]byte, 0)
	b1 = append(b1, b[:l] ... )
	b2 = append(b2, b[l:2*l] ... )
	b1 = append(b1, b[2*l:3*l] ... )
	b2 = append(b2, b[3*l:] ... )

	c1, c2 := big.NewInt(0), big.NewInt(0)
	c1.SetBytes(b1)
	c2.SetBytes(b2)

	return ElGamalUnwrap(c1, c2, prv.gam)
}
