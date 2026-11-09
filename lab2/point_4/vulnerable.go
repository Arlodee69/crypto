package point4

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	"cryptography/lab2/internal/random"
	point1 "cryptography/lab2/point_1"
	point2 "cryptography/lab2/point_2"
)

type VulnerableKey struct {
	N, E, D   *big.Int
	P, Q, Phi *big.Int
}

type VulnerableGenerator struct {
	bits       int
	confidence float64
	reader     io.Reader
	test       point2.PrimalityTest
	arithmetic point1.Service
}

func NewVulnerableGenerator(bits int, confidence float64, reader io.Reader) (*VulnerableGenerator, error) {
	if bits < 16 {
		return nil, fmt.Errorf("vulnerable generator requires at least 16 bits per prime")
	}
	if err := point2.ValidateConfidence(confidence); err != nil {
		return nil, err
	}
	if reader == nil {
		reader = rand.Reader
	}
	return &VulnerableGenerator{bits: bits, confidence: confidence, reader: reader, test: point2.NewMillerRabin(reader)}, nil
}

// Generate enforces p < q < 2p and 3d < floor(n^(1/4)). This is within
// Wiener's proven small-exponent range. These keys are intentionally insecure.
func (g *VulnerableGenerator) Generate(ctx context.Context) (*VulnerableKey, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		p, err := point2.GeneratePrime(ctx, g.test, g.confidence, g.bits, g.reader)
		if err != nil {
			return nil, err
		}
		q, err := point2.GeneratePrime(ctx, g.test, g.confidence, g.bits, g.reader)
		if err != nil {
			return nil, err
		}
		if p.Cmp(q) == 0 {
			continue
		}
		if p.Cmp(q) > 0 {
			p, q = q, p
		}
		n := new(big.Int).Mul(p, q)
		phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
		root, _ := g.arithmetic.FourthRoot(n)
		bound := new(big.Int).Quo(root, big.NewInt(3))
		limit := new(big.Int).Sub(bound, big.NewInt(3))
		if limit.Sign() <= 0 {
			continue
		}
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			d, err := random.Below(g.reader, limit)
			if err != nil {
				return nil, err
			}
			d.Add(d, big.NewInt(3))
			if g.arithmetic.GCD(d, phi).Cmp(big.NewInt(1)) != 0 {
				continue
			}
			e, err := g.arithmetic.ModInverse(d, phi)
			if err != nil {
				return nil, err
			}
			// Also verify the observable attack result before returning the example.
			attack, err := (WienerService{}).Attack(e, n)
			if err != nil {
				return nil, err
			}
			if !attack.Found || attack.D.Cmp(d) != 0 || attack.Phi.Cmp(phi) != 0 {
				break // probable-prime false positive or unsuitable pair; resample
			}
			return &VulnerableKey{N: n, E: e, D: d, P: p, Q: q, Phi: phi}, nil
		}
	}
}
