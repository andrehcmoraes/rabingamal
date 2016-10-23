// Package rabingamal combines the asymmetric algorithms Rabin and ElGamal.
package rabingamal

// File prime.go implements various prime and crypto utils.

import (
	"math/big"
	"math/rand"
	"time"
)

// Useful handles.
var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)
var bigTwo = big.NewInt(2)
var bigThree = big.NewInt(3)
var bigFour = big.NewInt(4)

// modSquareRoot returns the square root 'x' mod 'm', assuming that
// 'm' is a prime such that m = 3 mod 4.
func modSquareRoot(x, m *big.Int) *big.Int {
	z, a := big.NewInt(0), big.NewInt(0)

	z.Add(m, bigOne)
	z.Div(z, bigFour)
	return a.Exp(x, z, m)
}

// leadZeroes pad array 'a' with leading zeroes up to length 'l'.
func leadZeroes(a []byte, l int) []byte {
	l -= len(a)
	if l > 0 {
		z := make([]byte, l)
		for i := range z {
			z[i] = 0
		}
		a = append(z, a...)
	}
	return a
}

// xGCD implements the extended euclidean algorithmn on given numbers.
func xGCD(aa, bb *big.Int) (c, x, y *big.Int) {
	a, b := big.NewInt(0), big.NewInt(0)
	z, q := big.NewInt(0), big.NewInt(0)

	a.Set(aa)
	b.Set(bb)

	x, xx, y, yy := big.NewInt(0), big.NewInt(1), big.NewInt(1), big.NewInt(0)

	for b.Cmp(bigOne) > 0 {
		q.DivMod(a, b, z)
		a.Set(b)
		b.Set(z)

		z.Mul(q, x)
		z.Sub(xx, z)
		xx.Set(x)
		x.Set(z)

		z.Mul(q, y)
		z.Sub(yy, z)
		yy.Set(y)
		y.Set(z)
	}

	return a, x, y
}

// invMod implements the modular inverse x^(-1) mod m
func invMod(x, m *big.Int) *big.Int {
	_, y, _ := xGCD(x, m)
	return y.Mod(y, m)
}

// NewPrime generates a new prime 'p' with given bitSize.
// The prime is guaranteed to be such p = 3 mod 4.
func NewPrime(bitSize int64) *big.Int {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	if bitSize < 0 {
		panic("NewPrime: Invalid bitsize.")
	}

	n := big.NewInt(0)
	max := big.NewInt(0)
	bigSize := big.NewInt(bitSize)

	max.Exp(bigTwo, bigSize, nil)
	for {
		// Get new random.
		n.Rand(r, max)

		// Check number quality.
		if !qualityNumber(n, bigSize) {
			continue
		}

		// Survive 10 rounds of MillerRabin.
		if millerRabin(n, 10) {
			break
		}
	}

	return n
}

// qualityNumber increases the chance of a random number being prime.
func qualityNumber(n, bigSize *big.Int) bool {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	z := big.NewInt(0)
	min := big.NewInt(0)

	// min = 2^(size/2), the median element.
	min.Div(bigSize, bigTwo)
	min.Exp(bigTwo, min, nil)

	// Reject small numbers.
	if n.Cmp(min) < 0 {
		return false
	}

	// Modify even numbers.
	if z.Mod(n, bigTwo); z.Cmp(bigZero) == 0 {
		// Add either +1 or -1.
		if r.Intn(2) > 0 {
			n.Add(n, bigOne)
		} else {
			n.Sub(n, bigOne)
		}
	}

	// Ensure n = 3 mod 4.
	if z.Mod(n, bigFour); z.Cmp(bigThree) != 0 {
		// Add either (3-m) or -(m+1).
		n.Sub(n, z)
		if r.Intn(2) > 0 {
			n.Add(n, bigThree)
		} else {
			n.Sub(n, bigOne)
		}
	}

	// Good number.
	return true
}

// millerRabin performs the MillerRabin test to check if a number is prime.
func millerRabin(n *big.Int, k int) bool {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	z := big.NewInt(0)

	// Reject negatives and smaller numbers.
	if n.Cmp(bigTwo) < 0 {
		return false
	}

	// Return false for all even numbers, except 2.
	if z.Mod(n, bigTwo); z.Cmp(bigZero) == 0 {
		return n.Cmp(bigTwo) == 0
	}

	// p = n - 1.
	p := big.NewInt(0)
	p.Sub(n, bigOne)

	// q = n - 4.
	q := big.NewInt(0)
	q.Sub(n, bigFour)

	// p = 2^s * d.
	d, s := big.NewInt(0), big.NewInt(0)
	for {
		z.Add(s, bigOne)
		z.Exp(bigTwo, z, nil)
		z.DivMod(p, z, d)
		if d.Cmp(bigZero) > 0 {
			break
		}
		s.Add(s, bigOne)
	}
	z.Exp(bigTwo, s, nil)
	d.Div(p, z)

	a := big.NewInt(0)
	x := big.NewInt(0)
	for i := 0; i < k; i++ {
		// Pick a randomly in the range [2, n − 1].
		a.Rand(r, q)
		a.Add(a, bigTwo)

		// x = a ^ d mod n.
		x.Exp(a, d, n)

		// x == 1 mod n or x == (n - 1) mod n.
		if x.Cmp(bigOne) == 0 || x.Cmp(p) == 0 {
			continue
		}

		skip := false
		for j := big.NewInt(1); j.Cmp(s) < 0; j.Add(j, bigOne) {
			// x = x^2 mod n.
			x.Exp(x, bigTwo, n)

			// x^(2^r) mod n == 1, definitely composite.
			if x.Cmp(bigOne) == 0 {
				return false
			}

			// x^(2^r) mod n == n-1.
			if x.Cmp(p) == 0 {
				skip = true
				break
			}
		}

		// May yet be prime.
		if skip {
			continue
		}

		// Definitely composite.
		return false
	}

	// Possibly prime.
	return true
}
