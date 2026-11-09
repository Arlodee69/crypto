package point4

import (
	"context"
	"errors"
	"math/big"
	"math/rand"
	"testing"

	point1 "cryptography/lab2/point_1"
)

func TestConvergents(t *testing.T) {
	fractions, err := (WienerService{}).Convergents(big.NewInt(415), big.NewInt(93))
	want := [][2]int64{{4, 1}, {9, 2}, {58, 13}, {415, 93}}
	if err != nil || len(fractions) != len(want) {
		t.Fatal(fractions, err)
	}
	for i, f := range fractions {
		if f.Numerator.Int64() != want[i][0] || f.Denominator.Int64() != want[i][1] {
			t.Fatalf("convergent %d = %v/%v", i, f.Numerator, f.Denominator)
		}
	}
	if _, err := (WienerService{}).Convergents(big.NewInt(1), big.NewInt(0)); err == nil {
		t.Fatal("zero denominator")
	}
}

func TestKnownWienerVector(t *testing.T) {
	e, n := big.NewInt(17993), big.NewInt(90581)
	result, err := (WienerService{}).Attack(e, n)
	if err != nil || !result.Found || result.D.Int64() != 5 || result.Phi.Int64() != 89964 || result.P.Int64() != 239 || result.Q.Int64() != 379 {
		t.Fatalf("known attack vector: %+v %v", result, err)
	}
	if e.Int64() != 17993 || n.Int64() != 90581 {
		t.Fatal("attack mutated key")
	}
	if len(result.Convergents) < 2 || result.Convergents[0].Numerator.Sign() != 0 || result.Convergents[0].Denominator.Int64() != 1 {
		t.Fatal("missing initial convergent 0/1")
	}
	last := result.Convergents[len(result.Convergents)-1]
	if last.Numerator.Cmp(e) != 0 || last.Denominator.Cmp(n) != 0 {
		t.Fatal("not all convergents returned")
	}
	// Recovered d decrypts representatives including non-units p and q.
	s := point1.Service{}
	for _, m := range []int64{0, 1, 42, 239, 379, 90580} {
		c, _ := s.ModPow(big.NewInt(m), e, n)
		decoded, err := s.ModPow(c, result.D, n)
		if err != nil || decoded.Int64() != m {
			t.Fatal("recovered exponent does not decrypt", m)
		}
	}
}

func TestAttackFailureAndInvalidCandidates(t *testing.T) {
	s := WienerService{}
	result, err := s.Attack(big.NewInt(17), big.NewInt(3233))
	if err != nil || result.Found || result.D != nil || result.Phi != nil || len(result.Convergents) == 0 {
		t.Fatalf("unexpected success: %+v %v", result, err)
	}
	for _, pair := range [][2]int64{{1, 3233}, {0, 90581}, {17, 4}, {17, -3}} {
		if _, err := s.Attack(big.NewInt(pair[0]), big.NewInt(pair[1])); err == nil {
			t.Fatal("invalid key accepted", pair)
		}
	}
	for _, phi := range []int64{-1, 0, 1, 12, 3232, 3233, 3234} {
		if _, _, ok := s.RecoverFactors(big.NewInt(3233), big.NewInt(phi)); ok {
			t.Fatal("false factor recovery", phi)
		}
	}
	p, q, ok := s.RecoverFactors(big.NewInt(3233), big.NewInt(3120))
	if !ok || p.Int64() != 53 || q.Int64() != 61 {
		t.Fatal("factor recovery")
	}
}

func TestGeneratedVulnerableKeys(t *testing.T) {
	s := point1.Service{}
	for _, bits := range []int{16, 32, 128} {
		generator, err := NewVulnerableGenerator(bits, 0.99999999999, rand.New(rand.NewSource(int64(bits))))
		if err != nil {
			t.Fatal(err)
		}
		for count := 0; count < 3; count++ {
			key, err := generator.Generate(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if key.P.BitLen() != bits || key.Q.BitLen() != bits || key.P.Cmp(key.Q) >= 0 || key.Q.Cmp(new(big.Int).Lsh(new(big.Int).Set(key.P), 1)) >= 0 {
				t.Fatal("unbalanced prime sizes")
			}
			root, _ := s.FourthRoot(key.N)
			if new(big.Int).Mul(big.NewInt(3), key.D).Cmp(root) >= 0 {
				t.Fatal("Wiener bound not satisfied")
			}
			attack, err := (WienerService{}).Attack(key.E, key.N)
			if err != nil || !attack.Found || attack.D.Cmp(key.D) != 0 || attack.Phi.Cmp(key.Phi) != 0 {
				t.Fatal("generated key not recovered", err)
			}
		}
	}
	g, _ := NewVulnerableGenerator(16, 0.9, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.Generate(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation", err)
	}
	if _, err := NewVulnerableGenerator(15, 0.9, nil); err == nil {
		t.Fatal("invalid bit size")
	}
}
