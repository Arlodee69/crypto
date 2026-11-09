// Package point2 implements probabilistic primality tests using a shared
// template method and replaceable iteration behavior.
package point2

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"math/big"

	"cryptography/lab2/internal/random"
	point1 "cryptography/lab2/point_1"
)

type PrimalityTest interface {
	Test(ctx context.Context, n *big.Int, confidence float64) (bool, error)
}

// Iteration is the customization point of the Template Method pattern.
// Rounds must guarantee error <= 1-confidence for independent uniform bases.
type Iteration interface {
	Rounds(n *big.Int, confidence float64) (*big.Int, error)
	Check(arithmetic point1.Service, n, base *big.Int) (bool, error)
}

// Template owns the common algorithm; concrete tests embed it. Go has neither
// abstract classes nor inheritance, so composition supplies the same behavior.
type Template struct {
	iteration  Iteration
	reader     io.Reader
	arithmetic point1.Service
}

func NewTemplate(iteration Iteration, reader io.Reader) (*Template, error) {
	if iteration == nil {
		return nil, fmt.Errorf("iteration must not be nil")
	}
	if reader == nil {
		reader = rand.Reader
	}
	return &Template{iteration: iteration, reader: reader}, nil
}

func ValidateConfidence(confidence float64) error {
	if math.IsNaN(confidence) || math.IsInf(confidence, 0) || confidence < 0.5 || confidence >= 1 {
		return fmt.Errorf("confidence must be in [0.5, 1)")
	}
	return nil
}

// Rounds exposes the planned iteration count without starting an expensive test.
func (t *Template) Rounds(n *big.Int, confidence float64) (*big.Int, error) {
	if err := ValidateConfidence(confidence); err != nil {
		return nil, err
	}
	if n == nil || n.Cmp(big.NewInt(2)) < 0 {
		return nil, fmt.Errorf("round count requires n >= 2")
	}
	return t.iteration.Rounds(n, confidence)
}

// Test is the fixed template method: validation, trivial cases, round count,
// unbiased random bases, customized iteration, and early rejection.
// Confidence bounds false acceptance for a fixed composite; it is not a
// posterior probability that a particular accepted number is prime.
func (t *Template) Test(ctx context.Context, n *big.Int, confidence float64) (bool, error) {
	if err := ValidateConfidence(confidence); err != nil {
		return false, err
	}
	if n == nil {
		return false, fmt.Errorf("candidate must not be nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if n.Cmp(big.NewInt(2)) < 0 {
		return false, nil
	}
	if n.Cmp(big.NewInt(3)) <= 0 {
		return true, nil
	}
	if n.Bit(0) == 0 {
		return false, nil
	}
	rounds, err := t.iteration.Rounds(n, confidence)
	if err != nil {
		return false, err
	}
	if rounds == nil || rounds.Sign() <= 0 {
		return false, fmt.Errorf("iteration count must be positive")
	}
	limit := new(big.Int).Sub(n, big.NewInt(1))
	for i := new(big.Int); i.Cmp(rounds) < 0; i.Add(i, big.NewInt(1)) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		base, err := random.Below(t.reader, limit)
		if err != nil {
			return false, err
		}
		base.Add(base, big.NewInt(1)) // uniform in [1, n-1], including non-units
		passed, err := t.iteration.Check(t.arithmetic, n, base)
		if err != nil || !passed {
			return false, err
		}
	}
	return true, nil
}

// powerTwoRounds computes ceil(log_{2^bits}(1/(1-confidence))) exactly for
// the supplied float64, without rounding down near probability boundaries.
func powerTwoRounds(confidence float64, bits uint) (*big.Int, error) {
	if err := ValidateConfidence(confidence); err != nil {
		return nil, err
	}
	allowed := new(big.Rat).Sub(big.NewRat(1, 1), new(big.Rat).SetFloat64(confidence))
	errorBound := big.NewRat(1, 1)
	divisor := new(big.Rat).SetInt(new(big.Int).Lsh(big.NewInt(1), bits))
	rounds := int64(0)
	for errorBound.Cmp(allowed) > 0 {
		errorBound.Quo(errorBound, divisor)
		rounds++
	}
	return big.NewInt(rounds), nil
}

type Fermat struct{ *Template }
type SolovayStrassen struct{ *Template }
type MillerRabin struct{ *Template }

func NewFermat(reader io.Reader) *Fermat {
	t, _ := NewTemplate(fermatIteration{}, reader)
	return &Fermat{t}
}

func NewSolovayStrassen(reader io.Reader) *SolovayStrassen {
	t, _ := NewTemplate(solovayIteration{}, reader)
	return &SolovayStrassen{t}
}

func NewMillerRabin(reader io.Reader) *MillerRabin {
	t, _ := NewTemplate(millerIteration{}, reader)
	return &MillerRabin{t}
}

type fermatIteration struct{}

func (fermatIteration) Rounds(n *big.Int, confidence float64) (*big.Int, error) {
	r, err := powerTwoRounds(confidence, 1)
	if err != nil {
		return nil, err
	}
	root, err := (point1.Service{}).Sqrt(n)
	if err != nil {
		return nil, err
	}
	// If n is composite, its least prime divisor p <= floor(sqrt(n)).
	// At least (n/p-1)/(n-1) >= 1/(p+1) sampled bases are non-units.
	// Set B=floor(sqrt(n))+1. A block of B rounds has error
	// <= (1-1/B)^B < 1/2, even for Carmichael numbers.
	return r.Mul(r, root.Add(root, big.NewInt(1))), nil
}

func (fermatIteration) Check(s point1.Service, n, a *big.Int) (bool, error) {
	if s.GCD(a, n).Cmp(big.NewInt(1)) != 0 {
		return false, nil
	}
	r, err := s.ModPow(a, new(big.Int).Sub(n, big.NewInt(1)), n)
	return err == nil && r.Cmp(big.NewInt(1)) == 0, err
}

type solovayIteration struct{}

func (solovayIteration) Rounds(_ *big.Int, confidence float64) (*big.Int, error) {
	return powerTwoRounds(confidence, 1)
}

func (solovayIteration) Check(s point1.Service, n, a *big.Int) (bool, error) {
	symbol, err := s.Jacobi(a, n)
	if err != nil || symbol == 0 {
		return false, err
	}
	e := new(big.Int).Rsh(new(big.Int).Sub(n, big.NewInt(1)), 1)
	r, err := s.ModPow(a, e, n)
	if err != nil {
		return false, err
	}
	expected := new(big.Int).Mod(big.NewInt(int64(symbol)), n)
	return r.Cmp(expected) == 0, nil
}

type millerIteration struct{}

func (millerIteration) Rounds(_ *big.Int, confidence float64) (*big.Int, error) {
	return powerTwoRounds(confidence, 2)
}

func (millerIteration) Check(s point1.Service, n, a *big.Int) (bool, error) {
	minusOne := new(big.Int).Sub(n, big.NewInt(1))
	d := new(big.Int).Set(minusOne)
	powers := 0
	for d.Bit(0) == 0 {
		d.Rsh(d, 1)
		powers++
	}
	x, err := s.ModPow(a, d, n)
	if err != nil {
		return false, err
	}
	if x.Cmp(big.NewInt(1)) == 0 || x.Cmp(minusOne) == 0 {
		return true, nil
	}
	for r := 1; r < powers; r++ {
		x.Mul(x, x).Mod(x, n)
		if x.Cmp(minusOne) == 0 {
			return true, nil
		}
		if x.Cmp(big.NewInt(1)) == 0 {
			return false, nil
		}
	}
	return false, nil
}
