// Package point4 implements Wiener's continued-fraction attack and generation
// of deliberately vulnerable RSA key pairs.
package point4

import (
	"fmt"
	"math/big"

	point1 "cryptography/lab2/point_1"
)

type Fraction struct {
	Numerator   *big.Int
	Denominator *big.Int
}

type Result struct {
	Found       bool
	D, Phi      *big.Int
	P, Q        *big.Int
	Convergents []Fraction
}

type WienerService struct{ arithmetic point1.Service }

// Convergents computes all continued-fraction convergents of numerator/denominator.
func (WienerService) Convergents(numerator, denominator *big.Int) ([]Fraction, error) {
	if numerator == nil || denominator == nil || numerator.Sign() <= 0 || denominator.Sign() <= 0 {
		return nil, fmt.Errorf("fraction components must be positive")
	}
	x, y := new(big.Int).Set(numerator), new(big.Int).Set(denominator)
	p0, p1 := new(big.Int), big.NewInt(1)
	q0, q1 := big.NewInt(1), new(big.Int)
	fractions := make([]Fraction, 0)
	for y.Sign() != 0 {
		a, remainder := new(big.Int), new(big.Int)
		a.QuoRem(x, y, remainder)
		p := new(big.Int).Add(new(big.Int).Mul(a, p1), p0)
		q := new(big.Int).Add(new(big.Int).Mul(a, q1), q0)
		fractions = append(fractions, Fraction{new(big.Int).Set(p), new(big.Int).Set(q)})
		p0, p1, q0, q1 = p1, p, q1, q
		x, y = y, remainder
	}
	return fractions, nil
}

// RecoverFactors solves x^2 - (n-phi+1)x + n = 0 over positive integers.
// Invalid candidate phi values are ordinary unsuccessful attempts, not errors.
func (s WienerService) RecoverFactors(n, phi *big.Int) (p, q *big.Int, ok bool) {
	if n == nil || phi == nil || phi.Sign() <= 0 || phi.Cmp(n) >= 0 {
		return nil, nil, false
	}
	sum := new(big.Int).Add(new(big.Int).Sub(n, phi), big.NewInt(1))
	discriminant := new(big.Int).Sub(new(big.Int).Mul(sum, sum), new(big.Int).Lsh(new(big.Int).Set(n), 2))
	if discriminant.Sign() < 0 {
		return nil, nil, false
	}
	root, err := s.arithmetic.Sqrt(discriminant)
	if err != nil || new(big.Int).Mul(root, root).Cmp(discriminant) != 0 {
		return nil, nil, false
	}
	if sum.Bit(0) != root.Bit(0) {
		return nil, nil, false
	}
	p = new(big.Int).Rsh(new(big.Int).Sub(sum, root), 1)
	q = new(big.Int).Rsh(new(big.Int).Add(sum, root), 1)
	if p.Cmp(big.NewInt(1)) <= 0 || p.Cmp(q) == 0 || new(big.Int).Mul(p, q).Cmp(n) != 0 {
		return nil, nil, false
	}
	return p, q, true
}

// Attack returns all convergents, including when no private exponent is found.
// A failed attack does not by itself establish that a public key is secure.
func (s WienerService) Attack(e, n *big.Int) (*Result, error) {
	if e == nil || n == nil || e.Cmp(big.NewInt(1)) <= 0 || n.Cmp(big.NewInt(3)) <= 0 || n.Bit(0) == 0 {
		return nil, fmt.Errorf("RSA public key requires e > 1 and odd n > 3")
	}
	fractions, err := s.Convergents(e, n)
	if err != nil {
		return nil, err
	}
	result := &Result{Convergents: fractions}
	for _, f := range fractions {
		k, d := f.Numerator, f.Denominator
		if k.Sign() == 0 || d.Sign() == 0 {
			continue
		}
		edMinusOne := new(big.Int).Sub(new(big.Int).Mul(e, d), big.NewInt(1))
		phi, remainder := new(big.Int), new(big.Int)
		phi.QuoRem(edMinusOne, k, remainder)
		if remainder.Sign() != 0 {
			continue
		}
		p, q, found := s.RecoverFactors(n, phi)
		if found {
			result.Found = true
			result.D, result.Phi = new(big.Int).Set(d), phi
			result.P, result.Q = p, q
			break
		}
	}
	return result, nil
}
