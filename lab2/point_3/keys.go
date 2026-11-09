// Package point3 implements an educational textbook RSA service.
package point3

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"sync"

	point1 "cryptography/lab2/point_1"
	point2 "cryptography/lab2/point_2"
	point4 "cryptography/lab2/point_4"
)

// TestKind is the Go equivalent of the service's nested enum in the assignment.
// Go declares types at package scope; Service owns a KeyGenerator by composition.
type TestKind uint8

const (
	Fermat TestKind = iota
	SolovayStrassen
	MillerRabin
)

func (k TestKind) String() string {
	switch k {
	case Fermat:
		return "Fermat"
	case SolovayStrassen:
		return "Solovay-Strassen"
	case MillerRabin:
		return "Miller-Rabin"
	default:
		return "unknown"
	}
}

type PublicKey struct{ N, E *big.Int }
type PrivateKey struct{ N, D *big.Int }

type KeyPair struct {
	Public      PublicKey
	Private     PrivateKey
	P, Q, Phi   *big.Int
	FermatSteps *big.Int
}

func (k *KeyPair) clone() *KeyPair {
	return &KeyPair{
		Public:  PublicKey{new(big.Int).Set(k.Public.N), new(big.Int).Set(k.Public.E)},
		Private: PrivateKey{new(big.Int).Set(k.Private.N), new(big.Int).Set(k.Private.D)},
		P:       new(big.Int).Set(k.P), Q: new(big.Int).Set(k.Q), Phi: new(big.Int).Set(k.Phi),
		FermatSteps: new(big.Int).Set(k.FermatSteps),
	}
}

type KeyGenerator struct {
	mu         sync.Mutex
	test       point2.PrimalityTest
	confidence float64
	bits       int
	reader     io.Reader
	arithmetic point1.Service
}

func NewKeyGenerator(kind TestKind, confidence float64, primeBits int) (*KeyGenerator, error) {
	return newKeyGenerator(kind, confidence, primeBits, rand.Reader)
}

func newKeyGenerator(kind TestKind, confidence float64, primeBits int, reader io.Reader) (*KeyGenerator, error) {
	if primeBits < 16 {
		return nil, fmt.Errorf("RSA requires at least 16 bits per prime")
	}
	if err := point2.ValidateConfidence(confidence); err != nil {
		return nil, err
	}
	var test point2.PrimalityTest
	switch kind {
	case Fermat:
		test = point2.NewFermat(reader)
	case SolovayStrassen:
		test = point2.NewSolovayStrassen(reader)
	case MillerRabin:
		test = point2.NewMillerRabin(reader)
	default:
		return nil, fmt.Errorf("unknown primality test: %d", kind)
	}
	return &KeyGenerator{test: test, confidence: confidence, bits: primeBits, reader: reader}, nil
}

// FermatIterations returns the exact number of failed iterations of Fermat's
// factorization before reaching (p+q)/2, starting at ceil(sqrt(pq)).
func FermatIterations(p, q *big.Int) (*big.Int, error) {
	if p == nil || q == nil || p.Cmp(big.NewInt(3)) < 0 || q.Cmp(big.NewInt(3)) < 0 || p.Bit(0) == 0 || q.Bit(0) == 0 {
		return nil, fmt.Errorf("Fermat factors must be odd and at least 3")
	}
	n := new(big.Int).Mul(p, q)
	root, _ := (point1.Service{}).Sqrt(n)
	if new(big.Int).Mul(root, root).Cmp(n) < 0 {
		root.Add(root, big.NewInt(1))
	}
	middle := new(big.Int).Rsh(new(big.Int).Add(p, q), 1)
	return middle.Sub(middle, root), nil
}

// Generate can be called repeatedly. For prime bit length b it requires:
//   - at least 2^floor(b/2) failed Fermat factorization iterations;
//   - d >= 2^b > sqrt(n), well above Wiener's small-exponent range;
//   - unsuccessful execution of the implemented Wiener attack.
//
// Large b is essential: no choice makes a 32-bit modulus secure.
func (g *KeyGenerator) Generate(ctx context.Context) (*KeyPair, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	minimumFermat := new(big.Int).Lsh(big.NewInt(1), uint(g.bits/2))
	minimumD := new(big.Int).Lsh(big.NewInt(1), uint(g.bits))
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
		steps, _ := FermatIterations(p, q)
		if steps.Cmp(minimumFermat) < 0 {
			continue
		}
		n := new(big.Int).Mul(p, q)
		phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
		e := big.NewInt(65537)
		if g.arithmetic.GCD(e, phi).Cmp(big.NewInt(1)) != 0 {
			continue
		}
		d, err := g.arithmetic.ModInverse(e, phi)
		if err != nil {
			return nil, err
		}
		if d.Cmp(minimumD) < 0 {
			continue
		}
		attack, err := (point4.WienerService{}).Attack(e, n)
		if err != nil {
			return nil, err
		}
		if attack.Found {
			continue
		}
		return &KeyPair{
			Public:  PublicKey{new(big.Int).Set(n), e},
			Private: PrivateKey{new(big.Int).Set(n), d},
			P:       p, Q: q, Phi: phi, FermatSteps: steps,
		}, nil
	}
}
