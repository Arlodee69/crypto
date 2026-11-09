package point2

import (
	"context"
	"errors"
	"io"
	"math"
	"math/big"
	"math/rand"
	"testing"
	"time"

	point1 "cryptography/lab2/point_1"
)

func primeByDivision(n int64) bool {
	if n < 2 {
		return false
	}
	for d := int64(2); d*d <= n; d++ {
		if n%d == 0 {
			return false
		}
	}
	return true
}

func TestAllTestsAgainstTrialDivision(t *testing.T) {
	tests := map[string]PrimalityTest{
		"Fermat":          NewFermat(rand.New(rand.NewSource(11))),
		"SolovayStrassen": NewSolovayStrassen(rand.New(rand.NewSource(22))),
		"MillerRabin":     NewMillerRabin(rand.New(rand.NewSource(33))),
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			for n := int64(-2); n <= 350; n++ {
				candidate := big.NewInt(n)
				got, err := test.Test(context.Background(), candidate, 0.999999999)
				if err != nil || got != primeByDivision(n) || candidate.Int64() != n {
					t.Fatalf("n=%d: %v, %v", n, got, err)
				}
			}
			for _, n := range []int64{561, 1105, 1729, 2465, 2821, 6601, 2047, 1373653} {
				got, err := test.Test(context.Background(), big.NewInt(n), 0.999999999)
				if err != nil || got {
					t.Fatalf("accepted Carmichael number/pseudoprime %d: %v", n, err)
				}
			}
		})
	}
}

func TestKnownLyingBases(t *testing.T) {
	s := point1.Service{}
	if ok, err := (fermatIteration{}).Check(s, big.NewInt(561), big.NewInt(2)); err != nil || !ok {
		t.Fatal("561 must fool a single Fermat base 2")
	}
	if ok, _ := (fermatIteration{}).Check(s, big.NewInt(561), big.NewInt(3)); ok {
		t.Fatal("Fermat must reject a non-unit base")
	}
	if ok, _ := (millerIteration{}).Check(s, big.NewInt(2047), big.NewInt(2)); !ok {
		t.Fatal("2047 is a strong base-2 pseudoprime")
	}
	if ok, _ := (millerIteration{}).Check(s, big.NewInt(2047), big.NewInt(3)); ok {
		t.Fatal("base 3 should reject 2047")
	}
	// Exhaustively verify the claimed per-iteration liar bounds on small composites.
	for n := int64(9); n <= 151; n += 2 {
		if primeByDivision(n) {
			continue
		}
		ss, mr := int64(0), int64(0)
		for a := int64(1); a < n; a++ {
			if ok, _ := (solovayIteration{}).Check(s, big.NewInt(n), big.NewInt(a)); ok {
				ss++
			}
			if ok, _ := (millerIteration{}).Check(s, big.NewInt(n), big.NewInt(a)); ok {
				mr++
			}
		}
		if ss*2 > n-1 || mr*4 > n-1 {
			t.Fatalf("liar bound failed for %d: SS=%d MR=%d", n, ss, mr)
		}
	}
}

func TestRoundCountsAndConfidence(t *testing.T) {
	n := big.NewInt(101)
	for _, tc := range []struct {
		confidence float64
		ss, mr     int64
	}{{0.5, 1, 1}, {0.75, 2, 1}, {0.875, 3, 2}, {0.9375, 4, 2}} {
		ss, _ := NewSolovayStrassen(nil).Rounds(n, tc.confidence)
		mr, _ := NewMillerRabin(nil).Rounds(n, tc.confidence)
		f, _ := NewFermat(nil).Rounds(n, tc.confidence)
		if ss.Int64() != tc.ss || mr.Int64() != tc.mr || f.Int64() != 11*tc.ss {
			t.Fatalf("round counts at %v: %v %v %v", tc.confidence, ss, mr, f)
		}
	}
	for _, c := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), 0.4999, 1, 2} {
		if _, err := NewMillerRabin(nil).Test(nil, big.NewInt(2), c); err == nil {
			t.Fatalf("accepted invalid confidence %v even for trivial prime", c)
		}
	}
	if _, err := NewMillerRabin(nil).Test(nil, nil, 0.9); err == nil {
		t.Fatal("nil candidate")
	}
	if _, err := NewMillerRabin(nil).Rounds(n, math.Nextafter(1, 0)); err != nil {
		t.Fatal(err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

type spyIteration struct{ calls int }

func (*spyIteration) Rounds(*big.Int, float64) (*big.Int, error) {
	return big.NewInt(3), nil
}

func (s *spyIteration) Check(point1.Service, *big.Int, *big.Int) (bool, error) {
	s.calls++
	return s.calls < 2, nil
}

func TestTemplateCustomizationAndErrors(t *testing.T) {
	spy := &spyIteration{}
	template, err := NewTemplate(spy, zeroReader{})
	if err != nil {
		t.Fatal(err)
	}
	ok, err := template.Test(nil, big.NewInt(17), 0.9)
	if err != nil || ok || spy.calls != 2 {
		t.Fatal("template did not delegate or stop at first failing iteration")
	}
	if _, err := NewTemplate(nil, nil); err == nil {
		t.Fatal("nil strategy")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewFermat(nil).Test(ctx, big.NewInt(17), 0.9); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation not propagated")
	}
	if _, err := NewMillerRabin(&emptyReader{}).Test(nil, big.NewInt(17), 0.9); !errors.Is(err, io.EOF) {
		t.Fatalf("random error not propagated: %v", err)
	}
}

type emptyReader struct{}

func (*emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

func TestGeneratePrimeAndLargePrime(t *testing.T) {
	r := rand.New(rand.NewSource(44))
	p, err := GeneratePrime(nil, NewMillerRabin(r), 0.999999999, 17, r)
	if err != nil || p.BitLen() != 17 || !primeByDivision(p.Int64()) {
		t.Fatalf("prime generation: %v %v", p, err)
	}
	large := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1))
	for _, test := range []PrimalityTest{NewMillerRabin(r), NewSolovayStrassen(r)} {
		if ok, err := test.Test(nil, large, 0.999999999); err != nil || !ok {
			t.Fatal("rejected Mersenne prime", err)
		}
	}
	if _, err := GeneratePrime(nil, NewMillerRabin(r), 0.9, 1, r); err == nil {
		t.Fatal("accepted 1 bit")
	}
}

func TestCancellationDuringLongFermatTest(t *testing.T) {
	large := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	// Base 1 always passes, so only actual context cancellation can stop this
	// test before the astronomically large conservative round count is reached.
	if _, err := NewFermat(zeroReader{}).Test(ctx, large, 0.999); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("long-running test did not propagate its deadline: %v", err)
	}
}
