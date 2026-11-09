// Package random supplies unbiased integer sampling from random bytes.
package random

import (
	"fmt"
	"io"
	"math/big"
)

// Below uses rejection sampling, not reduction modulo limit.
func Below(reader io.Reader, limit *big.Int) (*big.Int, error) {
	if reader == nil || limit.Sign() <= 0 {
		return nil, fmt.Errorf("random sampling requires a reader and positive limit")
	}
	if limit.Cmp(big.NewInt(1)) == 0 {
		return new(big.Int), nil
	}
	bits := new(big.Int).Sub(limit, big.NewInt(1)).BitLen()
	data := make([]byte, (bits+7)/8)
	for {
		if _, err := io.ReadFull(reader, data); err != nil {
			return nil, fmt.Errorf("read random bytes: %w", err)
		}
		data[0] &= byte(0xff >> uint(len(data)*8-bits))
		x := new(big.Int).SetBytes(data)
		if x.Cmp(limit) < 0 {
			return x, nil
		}
	}
}

func OddWithBits(reader io.Reader, bits int) (*big.Int, error) {
	if reader == nil || bits < 2 {
		return nil, fmt.Errorf("candidate requires a reader and at least 2 bits")
	}
	data := make([]byte, (bits+7)/8)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, fmt.Errorf("read candidate bytes: %w", err)
	}
	data[0] &= byte(0xff >> uint(len(data)*8-bits))
	data[0] |= byte(1 << uint((bits-1)%8))
	data[len(data)-1] |= 1
	return new(big.Int).SetBytes(data), nil
}
