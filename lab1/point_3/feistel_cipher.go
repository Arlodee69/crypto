package point3

import (
	"fmt"
	"reflect"

	point2 "cryptography/lab1/point_2"
)

type FeistelCipher struct {
	blockSize   int
	rounds      int
	keyExpander point2.KeyExpander
	transformer point2.RoundTransformer
	roundKeys   [][]byte
}

func NewFeistelCipher(blockSize, rounds int, keyExpander point2.KeyExpander, transformer point2.RoundTransformer) (*FeistelCipher, error) {
	if blockSize <= 0 || blockSize%2 != 0 {
		return nil, fmt.Errorf("размер блока должен быть положительным и чётным: %d", blockSize)
	}
	if rounds <= 0 {
		return nil, fmt.Errorf("число раундов должно быть положительным: %d", rounds)
	}
	if isNil(keyExpander) || isNil(transformer) {
		return nil, fmt.Errorf("генератор ключей и раундовое преобразование не должны быть nil")
	}
	return &FeistelCipher{blockSize: blockSize, rounds: rounds, keyExpander: keyExpander, transformer: transformer}, nil
}

func isNil(value interface{}) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func (c *FeistelCipher) SetKey(key []byte) error {
	if c.keyExpander == nil {
		return fmt.Errorf("сеть Фейстеля должна быть создана через NewFeistelCipher")
	}
	keys, err := c.keyExpander.ExpandKey(append([]byte(nil), key...))
	if err != nil {
		return fmt.Errorf("генерация раундовых ключей: %w", err)
	}
	if len(keys) != c.rounds {
		return fmt.Errorf("генератор вернул %d ключей, требуется %d", len(keys), c.rounds)
	}
	ownedKeys := make([][]byte, len(keys))
	for i, roundKey := range keys {
		ownedKeys[i] = append([]byte(nil), roundKey...)
	}
	c.roundKeys = ownedKeys
	return nil
}

func (c *FeistelCipher) BlockSize() int { return c.blockSize }

func (c *FeistelCipher) EncryptBlock(block []byte) ([]byte, error) {
	return c.transform(block, false)
}

func (c *FeistelCipher) DecryptBlock(block []byte) ([]byte, error) {
	return c.transform(block, true)
}

func (c *FeistelCipher) transform(block []byte, decrypt bool) ([]byte, error) {
	if len(c.roundKeys) == 0 {
		return nil, fmt.Errorf("ключ шифрования не установлен")
	}
	if len(block) != c.blockSize {
		return nil, fmt.Errorf("длина блока должна быть %d байт, получено %d", c.blockSize, len(block))
	}
	half := c.blockSize / 2
	left := append([]byte(nil), block[:half]...)
	right := append([]byte(nil), block[half:]...)
	for round := 0; round < c.rounds; round++ {
		keyIndex := round
		if decrypt {
			keyIndex = c.rounds - 1 - round
		}
		transformed, err := c.transformer.Transform(append([]byte(nil), right...), append([]byte(nil), c.roundKeys[keyIndex]...))
		if err != nil {
			return nil, fmt.Errorf("раунд %d (ключ %d): %w", round+1, keyIndex+1, err)
		}
		if len(transformed) != half {
			return nil, fmt.Errorf("раунд %d: длина результата F должна быть %d байт, получено %d", round+1, half, len(transformed))
		}
		for i := range left {
			left[i] ^= transformed[i]
		}
		left, right = right, left
	}
	result := make([]byte, c.blockSize)
	copy(result, right)
	copy(result[half:], left)
	return result, nil
}
