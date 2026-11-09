package point1

import (
	"fmt"
	"math"
	"math/big"
)

type PrimePower struct {
	Prime    *big.Int
	Exponent uint
}

// Factorize uses trial division. This educational method is intended for small
// integers; RSA key generation computes phi from the already known p and q.
func (Service) Factorize(n *big.Int) ([]PrimePower, error) {
	if n.Sign() <= 0 {
		return nil, fmt.Errorf("factorization requires n > 0")
	}
	x := new(big.Int).Set(n)
	factors := make([]PrimePower, 0)
	d := big.NewInt(2)
	for new(big.Int).Mul(d, d).Cmp(x) <= 0 {
		count := uint(0)
		for new(big.Int).Mod(x, d).Sign() == 0 {
			x.Quo(x, d)
			count++
		}
		if count != 0 {
			factors = append(factors, PrimePower{new(big.Int).Set(d), count})
		}
		if d.Cmp(big.NewInt(2)) == 0 {
			d.SetInt64(3)
		} else {
			d.Add(d, big.NewInt(2))
		}
	}
	if x.Cmp(big.NewInt(1)) > 0 {
		factors = append(factors, PrimePower{x, 1})
	}
	return factors, nil
}

func (s Service) TotientDefinition(n uint64) (uint64, error) {
	if n == 0 {
		return 0, fmt.Errorf("totient requires n > 0")
	}
	count := uint64(0)
	// k < n avoids overflow at MaxUint64; phi(1) is handled explicitly.
	if n == 1 {
		return 1, nil
	}
	modulus := new(big.Int).SetUint64(n)
	for k := uint64(1); k < n; k++ {
		if s.GCD(new(big.Int).SetUint64(k), modulus).Cmp(big.NewInt(1)) == 0 {
			count++
		}
	}
	return count, nil
}

func (s Service) TotientFactorization(n *big.Int) (*big.Int, error) {
	factors, err := s.Factorize(n)
	if err != nil {
		return nil, err
	}
	result := new(big.Int).Set(n)
	for _, f := range factors {
		result.Quo(result, f.Prime)
		result.Mul(result, new(big.Int).Sub(f.Prime, big.NewInt(1)))
	}
	return result, nil
}

// TotientFourier evaluates the specified DFT sum directly, using compensated
// summation. The limit controls floating-point error and linear running time.
func (s Service) TotientFourier(n uint64) (uint64, error) {
	if n == 0 || n > 1_000_000 {
		return 0, fmt.Errorf("Fourier totient requires 1 <= n <= 1000000")
	}
	modulus := new(big.Int).SetUint64(n)
	sum, correction := 0.0, 0.0
	for k := uint64(1); k <= n; k++ {
		g := s.GCD(new(big.Int).SetUint64(k), modulus).Uint64()
		term := float64(g)*math.Cos(2*math.Pi*float64(k)/float64(n)) - correction
		next := sum + term
		correction = (next - sum) - term
		sum = next
	}
	rounded := math.Round(sum)
	if rounded < 1 || rounded > float64(n) || math.Abs(sum-rounded) > 1e-5 {
		return 0, fmt.Errorf("Fourier sum lost integer precision: %.17g", sum)
	}
	return uint64(rounded), nil
}

func (s Service) Carmichael(n *big.Int) (*big.Int, error) {
	factors, err := s.Factorize(n)
	if err != nil {
		return nil, err
	}
	result := big.NewInt(1) // lambda(1) = 1
	for _, f := range factors {
		power := big.NewInt(1)
		for i := uint(1); i < f.Exponent; i++ {
			power.Mul(power, f.Prime)
		}
		component := new(big.Int).Mul(power, new(big.Int).Sub(f.Prime, big.NewInt(1)))
		if f.Prime.Cmp(big.NewInt(2)) == 0 && f.Exponent >= 3 {
			component.Rsh(component, 1)
		}
		g := s.GCD(result, component)
		result.Quo(result, g).Mul(result, component)
	}
	return result, nil
}
