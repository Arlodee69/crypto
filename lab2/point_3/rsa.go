package point3

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"

	point1 "cryptography/lab2/point_1"
)

var ErrNoKey = errors.New("RSA key pair has not been generated")

// Service owns the key-generator service. A newly constructed service has no
// key: call GenerateKeys explicitly, with a cancellable context if necessary.
type Service struct {
	mu         sync.RWMutex
	generation sync.Mutex
	generator  *KeyGenerator
	keys       *KeyPair
	arithmetic point1.Service
}

func NewService(kind TestKind, confidence float64, primeBits int) (*Service, error) {
	// All three constructor parameters are delegated to the owned service.
	generator, err := NewKeyGenerator(kind, confidence, primeBits)
	if err != nil {
		return nil, err
	}
	return &Service{generator: generator}, nil
}

// GenerateKeys replaces the current key only after successful generation.
// Returned keys are copies, so callers cannot mutate the service's state.
func (s *Service) GenerateKeys(ctx context.Context) (*KeyPair, error) {
	s.generation.Lock()
	defer s.generation.Unlock()
	keys, err := s.generator.Generate(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.keys = keys.clone()
	s.mu.Unlock()
	return keys.clone(), nil
}

func (s *Service) Keys() (*KeyPair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.keys == nil {
		return nil, ErrNoKey
	}
	return s.keys.clone(), nil
}

func (s *Service) EncryptInteger(message *big.Int) (*big.Int, error) {
	keys, err := s.Keys()
	if err != nil {
		return nil, err
	}
	return s.transform(message, keys.Public.E, keys.Public.N)
}

func (s *Service) DecryptInteger(ciphertext *big.Int) (*big.Int, error) {
	keys, err := s.Keys()
	if err != nil {
		return nil, err
	}
	return s.transform(ciphertext, keys.Private.D, keys.Private.N)
}

func (s *Service) transform(value, exponent, modulus *big.Int) (*big.Int, error) {
	if value == nil || value.Sign() < 0 || value.Cmp(modulus) >= 0 {
		return nil, fmt.Errorf("RSA representative must be in [0, n)")
	}
	return s.arithmetic.ModPow(value, exponent, modulus)
}

// Encrypt splits arbitrary bytes into blocks. Each plaintext integer encodes
// 0x01 || payload, preserving leading/trailing zero bytes and the last length.
// Ciphertext blocks have a fixed modulus-sized width, in big-endian order.
// This is textbook RSA with framing, not cryptographic padding or authentication.
func (s *Service) Encrypt(data []byte) ([]byte, error) {
	keys, err := s.Keys()
	if err != nil {
		return nil, err
	}
	n, e := keys.Public.N, keys.Public.E
	payloadSize := (n.BitLen() - 2) / 8
	width := (n.BitLen() + 7) / 8
	result := make([]byte, 0)
	for offset := 0; offset < len(data); {
		size := payloadSize
		if len(data)-offset < size {
			size = len(data) - offset
		}
		block := make([]byte, size+1)
		block[0] = 1
		copy(block[1:], data[offset:offset+size])
		ciphertext, err := s.transform(new(big.Int).SetBytes(block), e, n)
		if err != nil {
			return nil, err
		}
		encoded := make([]byte, width)
		ciphertext.FillBytes(encoded)
		result = append(result, encoded...)
		offset += size
	}
	return result, nil
}

func (s *Service) Decrypt(data []byte) ([]byte, error) {
	keys, err := s.Keys()
	if err != nil {
		return nil, err
	}
	n, d := keys.Private.N, keys.Private.D
	payloadSize := (n.BitLen() - 2) / 8
	width := (n.BitLen() + 7) / 8
	if len(data)%width != 0 {
		return nil, fmt.Errorf("ciphertext length must be a multiple of %d", width)
	}
	result := make([]byte, 0)
	for offset := 0; offset < len(data); offset += width {
		message, err := s.transform(new(big.Int).SetBytes(data[offset:offset+width]), d, n)
		if err != nil {
			return nil, err
		}
		block := message.Bytes()
		if len(block) < 2 || len(block) > payloadSize+1 || block[0] != 1 {
			return nil, fmt.Errorf("invalid plaintext framing at ciphertext offset %d", offset)
		}
		if offset+width < len(data) && len(block) != payloadSize+1 {
			return nil, fmt.Errorf("short plaintext block before final block")
		}
		result = append(result, block[1:]...)
	}
	return result, nil
}
