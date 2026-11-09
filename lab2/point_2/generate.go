package point2

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	"cryptography/lab2/internal/random"
)

// GeneratePrime repeatedly samples odd integers of exactly bits bits and tests
// them with the supplied implementation. Cancellation is checked per candidate
// and per primality iteration. A reader must not block indefinitely.
func GeneratePrime(ctx context.Context, test PrimalityTest, confidence float64, bits int, reader io.Reader) (*big.Int, error) {
	if bits < 2 || test == nil {
		return nil, fmt.Errorf("prime generation requires bits >= 2 and a test")
	}
	if err := ValidateConfidence(confidence); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if reader == nil {
		reader = rand.Reader
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := random.OddWithBits(reader, bits)
		if err != nil {
			return nil, err
		}
		ok, err := test.Test(ctx, n, confidence)
		if err != nil {
			return nil, err
		}
		if ok {
			return n, nil
		}
	}
}
