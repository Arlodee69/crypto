package point1_test

import (
	"math/big"
	"testing"
)

func gcdSmall(a, b int64) int64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func TestTotientThreeWays(t *testing.T) {
	for n := uint64(1); n <= 350; n++ {
		want := uint64(0)
		for k := uint64(1); k <= n; k++ {
			if gcdSmall(int64(k), int64(n)) == 1 {
				want++
			}
		}
		a, ea := service.TotientDefinition(n)
		b, eb := service.TotientFactorization(new(big.Int).SetUint64(n))
		c, ec := service.TotientFourier(n)
		if ea != nil || eb != nil || ec != nil || a != want || b.Uint64() != want || c != want {
			t.Fatalf("phi(%d): %d %v %d, want %d; errors: %v %v %v", n, a, b, c, want, ea, eb, ec)
		}
	}
	if _, err := service.TotientDefinition(0); err == nil {
		t.Fatal("phi(0)")
	}
	if _, err := service.TotientFactorization(big.NewInt(0)); err == nil {
		t.Fatal("phi(0)")
	}
	for _, n := range []uint64{0, 1_000_001} {
		if _, err := service.TotientFourier(n); err == nil {
			t.Fatal("invalid Fourier domain")
		}
	}
}

func TestCarmichaelByDefinition(t *testing.T) {
	for n := int64(1); n <= 100; n++ {
		want := int64(1)
		for ; ; want++ {
			ok := true
			for a := int64(1); a < n; a++ {
				if gcdSmall(a, n) != 1 {
					continue
				}
				v := int64(1)
				for e := int64(0); e < want; e++ {
					v = v * a % n
				}
				if v != 1 {
					ok = false
					break
				}
			}
			if ok {
				break
			}
		}
		got, err := service.Carmichael(big.NewInt(n))
		if err != nil || got.Int64() != want {
			t.Fatalf("lambda(%d) = %v, want %d: %v", n, got, want, err)
		}
	}
	for n, want := range map[int64]int64{561: 80, 1105: 48, 1729: 36, 1024: 256} {
		got, err := service.Carmichael(big.NewInt(n))
		if err != nil || got.Int64() != want {
			t.Fatalf("lambda(%d) = %v, want %d", n, got, want)
		}
	}
}

func TestFourierPrecisionAtUpperBoundary(t *testing.T) {
	got, err := service.TotientFourier(1_000_000)
	// 10^6 = 2^6 * 5^6, so phi = 10^6*(1-1/2)*(1-1/5).
	if err != nil || got != 400_000 {
		t.Fatalf("Fourier precision at upper boundary: %d, %v", got, err)
	}
}
