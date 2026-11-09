package point3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/big"
	"math/rand"
	"sync"
	"testing"

	point4 "cryptography/lab2/point_4"
)

func seededService(t *testing.T, kind TestKind, bits int) *Service {
	t.Helper()
	g, err := newKeyGenerator(kind, 0.999999999, bits, rand.New(rand.NewSource(100+int64(kind)+int64(bits))))
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{generator: g}
	if _, err := s.GenerateKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

func assertProtected(t *testing.T, k *KeyPair, bits int) {
	t.Helper()
	if k.P.BitLen() != bits || k.Q.BitLen() != bits || k.P.Cmp(k.Q) == 0 {
		t.Fatal("incorrect prime sizes")
	}
	// Library primality is used only as an independent oracle in tests.
	if !k.P.ProbablyPrime(32) || !k.Q.ProbablyPrime(32) {
		t.Fatal("composite key factor")
	}
	n := new(big.Int).Mul(k.P, k.Q)
	phi := new(big.Int).Mul(new(big.Int).Sub(k.P, big.NewInt(1)), new(big.Int).Sub(k.Q, big.NewInt(1)))
	if n.Cmp(k.Public.N) != 0 || n.Cmp(k.Private.N) != 0 || phi.Cmp(k.Phi) != 0 {
		t.Fatal("incorrect n or phi")
	}
	if new(big.Int).Mod(new(big.Int).Mul(k.Public.E, k.Private.D), phi).Cmp(big.NewInt(1)) != 0 {
		t.Fatal("incorrect modular inverse")
	}
	steps, err := FermatIterations(k.P, k.Q)
	if err != nil || steps.Cmp(new(big.Int).Lsh(big.NewInt(1), uint(bits/2))) < 0 || steps.Cmp(k.FermatSteps) != 0 {
		t.Fatal("insufficient Fermat distance")
	}
	if k.Private.D.Cmp(new(big.Int).Lsh(big.NewInt(1), uint(bits))) < 0 {
		t.Fatal("small private exponent")
	}
	result, err := (point4.WienerService{}).Attack(k.Public.E, k.Public.N)
	if err != nil || result.Found {
		t.Fatal("Wiener recovered protected key")
	}
}

func TestGeneratorsAllPrimalityKinds(t *testing.T) {
	for _, kind := range []TestKind{Fermat, SolovayStrassen, MillerRabin} {
		t.Run(kind.String(), func(t *testing.T) {
			s := seededService(t, kind, 16)
			first, _ := s.Keys()
			assertProtected(t, first, 16)
			second, err := s.GenerateKeys(nil)
			if err != nil {
				t.Fatal(err)
			}
			assertProtected(t, second, 16)
			if first.Public.N.Cmp(second.Public.N) == 0 {
				t.Fatal("regeneration did not produce new key")
			}
		})
	}
	assertProtected(t, mustKeys(t, seededService(t, MillerRabin, 128)), 128)
}

func mustKeys(t *testing.T, s *Service) *KeyPair {
	t.Helper()
	k, err := s.Keys()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKnownRSAVectorAndNonUnits(t *testing.T) {
	s := &Service{keys: &KeyPair{
		Public:  PublicKey{big.NewInt(3233), big.NewInt(17)},
		Private: PrivateKey{big.NewInt(3233), big.NewInt(2753)},
		P:       big.NewInt(61), Q: big.NewInt(53), Phi: big.NewInt(3120), FermatSteps: big.NewInt(0),
	}}
	c, err := s.EncryptInteger(big.NewInt(65))
	if err != nil || c.Int64() != 2790 {
		t.Fatal("known encryption vector", c, err)
	}
	for _, m := range []int64{0, 1, 42, 53, 61, 65, 3232} {
		c, err := s.EncryptInteger(big.NewInt(m))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := s.DecryptInteger(c)
		if err != nil || decoded.Int64() != m {
			t.Fatal("RSA integer round trip", m, err)
		}
	}
	for _, m := range []*big.Int{nil, big.NewInt(-1), big.NewInt(3233)} {
		if _, err := s.EncryptInteger(m); err == nil {
			t.Fatal("accepted invalid representative")
		}
		if _, err := s.DecryptInteger(m); err == nil {
			t.Fatal("accepted invalid representative")
		}
	}
}

func TestBytesRoundTripAndMalformedCiphertext(t *testing.T) {
	s := seededService(t, MillerRabin, 32)
	k := mustKeys(t, s)
	payload := (k.Public.N.BitLen() - 2) / 8
	width := (k.Public.N.BitLen() + 7) / 8
	samples := [][]byte{nil, {}, {0}, {0, 0, 0}, {255, 0, 1, 0, 255}, []byte("Лабораторная работа №2: RSA 🔑\x00\x00")}
	for size := 0; size <= 3*payload+1; size++ {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i * 73)
		}
		samples = append(samples, data)
	}
	samples = append(samples, make([]byte, 1024))
	for _, data := range samples {
		before := append([]byte(nil), data...)
		encrypted, err := s.Encrypt(data)
		if err != nil {
			t.Fatal(err)
		}
		cipherBefore := append([]byte(nil), encrypted...)
		decoded, err := s.Decrypt(encrypted)
		if err != nil || !bytes.Equal(decoded, data) || !bytes.Equal(before, data) || !bytes.Equal(cipherBefore, encrypted) {
			t.Fatalf("byte round trip length %d: %v", len(data), err)
		}
	}
	for _, invalid := range [][]byte{{1}, make([]byte, width), bytes.Repeat([]byte{255}, width)} {
		if _, err := s.Decrypt(invalid); err == nil {
			t.Fatal("accepted invalid ciphertext")
		}
	}
	if payload > 1 {
		short, _ := s.Encrypt([]byte{1})
		if _, err := s.Decrypt(append(append([]byte(nil), short...), short...)); err == nil {
			t.Fatal("accepted short block before final block")
		}
	}
}

func TestKeyOwnershipCancellationAndConcurrency(t *testing.T) {
	s := seededService(t, MillerRabin, 32)
	original := mustKeys(t, s)
	external := mustKeys(t, s)
	external.Public.N.SetInt64(1)
	external.Private.D.SetInt64(1)
	external.P.SetInt64(1)
	if mustKeys(t, s).Public.N.Cmp(original.Public.N) != 0 || mustKeys(t, s).Private.D.Cmp(original.Private.D) != 0 {
		t.Fatal("external mutation reached service")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.GenerateKeys(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled generation", err)
	}
	if mustKeys(t, s).Public.N.Cmp(original.Public.N) != 0 {
		t.Fatal("failed generation replaced current key")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			message := []byte{0, 1, 2, 255, 0}
			c, err := s.Encrypt(message)
			if err != nil {
				t.Error(err)
				return
			}
			m, err := s.Decrypt(c)
			if err != nil || !bytes.Equal(m, message) {
				t.Error("concurrent round trip", err)
			}
		}()
	}
	wg.Wait()
}

func TestConstructorsAndUninitializedService(t *testing.T) {
	for _, tc := range []struct {
		kind       TestKind
		confidence float64
		bits       int
	}{{99, 0.9, 16}, {MillerRabin, 1, 16}, {MillerRabin, 0.49, 16}, {MillerRabin, 0.9, 15}} {
		if _, err := NewService(tc.kind, tc.confidence, tc.bits); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	s, err := NewService(MillerRabin, 0.99, 32)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Keys(); !errors.Is(err, ErrNoKey) {
		t.Fatal("missing key error")
	}
	if _, err := s.Encrypt(nil); !errors.Is(err, ErrNoKey) {
		t.Fatal("missing key error")
	}
	if _, err := s.Decrypt(nil); !errors.Is(err, ErrNoKey) {
		t.Fatal("missing key error")
	}
	g, _ := newKeyGenerator(MillerRabin, 0.9, 16, &emptyReader{})
	if _, err := g.Generate(nil); !errors.Is(err, io.EOF) {
		t.Fatal("random failure", err)
	}
}

type emptyReader struct{}

func (*emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

func TestFermatIterationFormula(t *testing.T) {
	// Compare the analytical distance against actual Fermat factorization.
	for _, pair := range [][2]int64{{53, 61}, {3, 101}, {101, 1009}, {239, 379}} {
		n := pair[0] * pair[1]
		a := int64(0)
		for a*a < n {
			a++
		}
		steps := int64(0)
		for ; ; a, steps = a+1, steps+1 {
			b2 := a*a - n
			b := int64(0)
			for b*b < b2 {
				b++
			}
			if b*b == b2 {
				break
			}
		}
		got, err := FermatIterations(big.NewInt(pair[0]), big.NewInt(pair[1]))
		if err != nil || got.Int64() != steps {
			t.Fatalf("Fermat distance for %v: %v, want %d", pair, got, steps)
		}
	}
}
