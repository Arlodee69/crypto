package point1_test

import (
	"math/big"
	"testing"

	point1 "cryptography/lab2/point_1"
)

var service point1.Service

func TestGCDAndBezout(t *testing.T) {
	for a := int64(-35); a <= 35; a++ {
		for b := int64(-35); b <= 35; b++ {
			x, y := big.NewInt(a), big.NewInt(b)
			want := new(big.Int).GCD(nil, nil, x, y) // independent test oracle only
			g, u, v := service.ExtendedGCD(x, y)
			identity := new(big.Int).Add(new(big.Int).Mul(x, u), new(big.Int).Mul(y, v))
			if g.Cmp(want) != 0 || identity.Cmp(g) != 0 || service.GCD(x, y).Cmp(want) != 0 || service.BinaryGCD(x, y).Cmp(want) != 0 {
				t.Fatalf("GCD/Bezout mismatch for %d, %d", a, b)
			}
			if x.Int64() != a || y.Int64() != b {
				t.Fatal("input mutated")
			}
		}
	}
	a := new(big.Int).Lsh(big.NewInt(45), 521)
	b := new(big.Int).Lsh(big.NewInt(75), 387)
	want := new(big.Int).Lsh(big.NewInt(15), 387)
	if service.BinaryGCD(a, b).Cmp(want) != 0 || service.GCD(a, b).Cmp(want) != 0 {
		t.Fatal("large GCD")
	}
}

func TestModPowAndInverse(t *testing.T) {
	for a := int64(-12); a <= 12; a++ {
		for e := int64(0); e < 12; e++ {
			for m := int64(1); m < 25; m++ {
				x, y, z := big.NewInt(a), big.NewInt(e), big.NewInt(m)
				got, err := service.ModPow(x, y, z)
				want := new(big.Int).Exp(x, y, z) // test oracle, not service implementation
				if err != nil || got.Cmp(want) != 0 || x.Int64() != a || y.Int64() != e || z.Int64() != m {
					t.Fatalf("ModPow(%d,%d,%d): %v %v", a, e, m, got, err)
				}
			}
		}
	}
	for _, m := range []int64{0, -1} {
		if _, err := service.ModPow(big.NewInt(2), big.NewInt(3), big.NewInt(m)); err == nil {
			t.Fatal("accepted nonpositive modulus")
		}
	}
	if _, err := service.ModPow(big.NewInt(2), big.NewInt(-1), big.NewInt(5)); err == nil {
		t.Fatal("accepted negative exponent")
	}
	inv, err := service.ModInverse(big.NewInt(-3), big.NewInt(11))
	if err != nil || inv.Int64() != 7 {
		t.Fatal("negative modular inverse")
	}
	if _, err := service.ModInverse(big.NewInt(6), big.NewInt(9)); err == nil {
		t.Fatal("accepted noninvertible value")
	}
}

func TestSymbols(t *testing.T) {
	for n := int64(1); n < 150; n += 2 {
		for a := int64(-150); a < 150; a++ {
			x, y := big.NewInt(a), big.NewInt(n)
			got, err := service.Jacobi(x, y)
			if err != nil || got != big.Jacobi(x, y) {
				t.Fatalf("Jacobi(%d,%d) = %d, %v", a, n, got, err)
			}
		}
	}
	for _, p := range []int64{2, 3, 5, 7, 11, 31, 97} {
		for a := int64(-p); a <= p; a++ {
			r := (a%p + p) % p
			want := -1
			if r == 0 {
				want = 0
			} else {
				for x := int64(1); x < p; x++ {
					if x*x%p == r {
						want = 1
					}
				}
			}
			got, err := service.Legendre(big.NewInt(a), big.NewInt(p))
			if err != nil || got != want {
				t.Fatalf("Legendre(%d,%d) = %d, want %d: %v", a, p, got, want, err)
			}
		}
	}
	for _, n := range []int64{-1, 0, 2, 4} {
		if _, err := service.Jacobi(big.NewInt(1), big.NewInt(n)); err == nil {
			t.Fatal("invalid Jacobi denominator accepted")
		}
	}
}

func TestRoots(t *testing.T) {
	for n := int64(0); n < 3000; n++ {
		r, err := service.Sqrt(big.NewInt(n))
		if err != nil || r.Int64()*r.Int64() > n || (r.Int64()+1)*(r.Int64()+1) <= n {
			t.Fatalf("sqrt(%d) = %v, %v", n, r, err)
		}
	}
	x := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 503), big.NewInt(17))
	square := new(big.Int).Mul(x, x)
	for _, delta := range []int64{-1, 0, 1} {
		n := new(big.Int).Add(square, big.NewInt(delta))
		r, err := service.Sqrt(n)
		want := new(big.Int).Set(x)
		if delta == -1 {
			want.Sub(want, big.NewInt(1))
		}
		if err != nil || r.Cmp(want) != 0 {
			t.Fatal("large integer square root")
		}
	}
	if _, err := service.Sqrt(big.NewInt(-1)); err == nil {
		t.Fatal("negative square root")
	}
}
