package random

import (
	"bytes"
	"errors"
	"io"
	"math/big"
	"testing"
)

func TestRejectionSampling(t *testing.T) {
	// 15 is rejected; 9 is accepted. Modulo reduction would have returned 5.
	r := bytes.NewReader([]byte{15, 9})
	n, err := Below(r, big.NewInt(10))
	if err != nil || n.Int64() != 9 || r.Len() != 0 {
		t.Fatal("rejection sampling", n, err)
	}
	if n, err := Below(bytes.NewReader(nil), big.NewInt(1)); err != nil || n.Sign() != 0 {
		t.Fatal("unit limit")
	}
	if _, err := Below(bytes.NewReader(nil), big.NewInt(2)); !errors.Is(err, io.EOF) {
		t.Fatal("random failure", err)
	}
}

func TestCandidateWidth(t *testing.T) {
	for bits := 2; bits <= 129; bits++ {
		for _, fill := range []byte{0, 255} {
			n, err := OddWithBits(bytes.NewReader(bytes.Repeat([]byte{fill}, (bits+7)/8)), bits)
			if err != nil || n.BitLen() != bits || n.Bit(0) != 1 {
				t.Fatalf("candidate bits=%d: %v %v", bits, n, err)
			}
		}
	}
}
