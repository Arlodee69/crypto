// Package point1 implements the stateless arithmetic service from task 1.
// Integer arguments must be non-nil. No method modifies its arguments.
package point1

import (
	"fmt"
	"math/big"
)

// Service has no state and its zero value is ready for concurrent use.
type Service struct{}

// GCD uses the Euclidean algorithm; GCD(0, 0) = 0.
func (Service) GCD(a, b *big.Int) *big.Int {
	x, y := new(big.Int).Abs(a), new(big.Int).Abs(b)
	for y.Sign() != 0 {
		x, y = y, new(big.Int).Mod(x, y)
	}
	return x
}

// ExtendedGCD returns nonnegative g and coefficients such that ax + by = g.
func (Service) ExtendedGCD(a, b *big.Int) (g, x, y *big.Int) {
	oldR, r := new(big.Int).Abs(a), new(big.Int).Abs(b)
	oldS, s := big.NewInt(1), new(big.Int)
	oldT, t := new(big.Int), big.NewInt(1)
	for r.Sign() != 0 {
		q := new(big.Int).Quo(oldR, r)
		oldR, r = r, new(big.Int).Sub(oldR, new(big.Int).Mul(q, r))
		oldS, s = s, new(big.Int).Sub(oldS, new(big.Int).Mul(q, s))
		oldT, t = t, new(big.Int).Sub(oldT, new(big.Int).Mul(q, t))
	}
	if a.Sign() < 0 {
		oldS.Neg(oldS)
	}
	if b.Sign() < 0 {
		oldT.Neg(oldT)
	}
	return oldR, oldS, oldT
}

// BinaryGCD uses Stein's algorithm (shifts, subtraction and comparison).
func (Service) BinaryGCD(a, b *big.Int) *big.Int {
	x, y := new(big.Int).Abs(a), new(big.Int).Abs(b)
	if x.Sign() == 0 {
		return y
	}
	if y.Sign() == 0 {
		return x
	}
	shift := uint(0)
	for x.Bit(0) == 0 && y.Bit(0) == 0 {
		x.Rsh(x, 1)
		y.Rsh(y, 1)
		shift++
	}
	for x.Bit(0) == 0 {
		x.Rsh(x, 1)
	}
	for y.Sign() != 0 {
		for y.Bit(0) == 0 {
			y.Rsh(y, 1)
		}
		if x.Cmp(y) > 0 {
			x, y = y, x
		}
		y.Sub(y, x)
	}
	return x.Lsh(x, shift)
}

// ModPow implements square-and-multiply, including exponent 0 and modulus 1.
func (Service) ModPow(base, exponent, modulus *big.Int) (*big.Int, error) {
	if exponent.Sign() < 0 || modulus.Sign() <= 0 {
		return nil, fmt.Errorf("exponent must be nonnegative and modulus positive")
	}
	result := new(big.Int).Mod(big.NewInt(1), modulus)
	x := new(big.Int).Mod(base, modulus)
	for i := 0; i < exponent.BitLen(); i++ {
		if exponent.Bit(i) == 1 {
			result.Mul(result, x).Mod(result, modulus)
		}
		x.Mul(x, x).Mod(x, modulus)
	}
	return result, nil
}

func (s Service) ModInverse(a, modulus *big.Int) (*big.Int, error) {
	if modulus.Cmp(big.NewInt(2)) < 0 {
		return nil, fmt.Errorf("modulus must be at least 2")
	}
	g, x, _ := s.ExtendedGCD(a, modulus)
	if g.Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("inverse does not exist")
	}
	return x.Mod(x, modulus), nil
}

// Jacobi uses quadratic reciprocity, and accepts any positive odd denominator.
// In particular (a/1) = 1, including a = 0.
func (Service) Jacobi(a, n *big.Int) (int, error) {
	if n.Sign() <= 0 || n.Bit(0) == 0 {
		return 0, fmt.Errorf("Jacobi denominator must be positive and odd")
	}
	x, y := new(big.Int).Mod(a, n), new(big.Int).Set(n)
	sign := 1
	for x.Sign() != 0 {
		for x.Bit(0) == 0 {
			x.Rsh(x, 1)
			r := new(big.Int).And(y, big.NewInt(7)).Int64()
			if r == 3 || r == 5 {
				sign = -sign
			}
		}
		x, y = y, x
		if x.Bit(1) == 1 && y.Bit(1) == 1 {
			sign = -sign
		}
		x.Mod(x, y)
	}
	if y.Cmp(big.NewInt(1)) != 0 {
		return 0, nil
	}
	return sign, nil
}

// Legendre uses Euler's criterion. The caller must supply a prime p.
// Testing primality is deliberately separate from evaluating the symbol.
func (s Service) Legendre(a, p *big.Int) (int, error) {
	if p.Cmp(big.NewInt(2)) == 0 {
		return int(a.Bit(0)), nil
	}
	if p.Cmp(big.NewInt(3)) < 0 || p.Bit(0) == 0 {
		return 0, fmt.Errorf("Legendre denominator must be prime")
	}
	e := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	r, err := s.ModPow(a, e, p)
	if err != nil {
		return 0, err
	}
	if r.Sign() == 0 {
		return 0, nil
	}
	if r.Cmp(big.NewInt(1)) == 0 {
		return 1, nil
	}
	if r.Cmp(new(big.Int).Sub(p, big.NewInt(1))) == 0 {
		return -1, nil
	}
	return 0, fmt.Errorf("Euler criterion failed: denominator is not prime")
}

// Sqrt returns floor(sqrt(n)), using integer Newton iteration.
func (Service) Sqrt(n *big.Int) (*big.Int, error) {
	if n.Sign() < 0 {
		return nil, fmt.Errorf("square root of a negative integer")
	}
	if n.Cmp(big.NewInt(2)) < 0 {
		return new(big.Int).Set(n), nil
	}
	x := new(big.Int).Lsh(big.NewInt(1), uint((n.BitLen()+1)/2))
	for {
		y := new(big.Int).Rsh(new(big.Int).Add(x, new(big.Int).Quo(n, x)), 1)
		if y.Cmp(x) >= 0 {
			return x, nil
		}
		x = y
	}
}

func (s Service) FourthRoot(n *big.Int) (*big.Int, error) {
	r, err := s.Sqrt(n)
	if err != nil {
		return nil, err
	}
	return s.Sqrt(r)
}
