// Package point6 реализует DEAL на базе сети Фейстеля и DES из пунктов 3 и 4.
package point6

import (
	"fmt"

	"cryptography/lab1/point_2"
	"cryptography/lab1/point_3"
	"cryptography/lab1/point_4"
)

const BlockSize = 16

// DEALCipher обрабатывает 128-битные блоки. SetKey выбирает 6 раундов для
// ключей 128/192 бит и 8 для 256 бит. Ключ настраивается до обработки данных.
type DEALCipher struct{ network *point3.FeistelCipher }

var _ point2.SymmetricCipher = (*DEALCipher)(nil)
var _ point2.KeyExpander = DEALKeyExpander{}
var _ point2.RoundTransformer = DESAdapter{}

func NewDEALCipher() *DEALCipher { return &DEALCipher{} }

func roundsForKey(size int) (int, error) {
	switch size {
	case 16, 24:
		return 6, nil
	case 32:
		return 8, nil
	default:
		return 0, fmt.Errorf("ключ DEAL должен содержать 16, 24 или 32 байта, получено %d", size)
	}
}

func (c *DEALCipher) SetKey(key []byte) error {
	rounds, err := roundsForKey(len(key))
	if err != nil {
		return err
	}
	network, err := point3.NewFeistelCipher(BlockSize, rounds, DEALKeyExpander{}, DESAdapter{})
	if err != nil {
		return err
	}
	if err := network.SetKey(key); err != nil {
		return err
	}
	// Неудачная настройка не уничтожает ранее установленный ключ.
	c.network = network
	return nil
}

func (c *DEALCipher) BlockSize() int { return BlockSize }

func (c *DEALCipher) EncryptBlock(block []byte) ([]byte, error) {
	if c.network == nil {
		return nil, fmt.Errorf("ключ DEAL не установлен")
	}
	return c.network.EncryptBlock(block)
}

func (c *DEALCipher) DecryptBlock(block []byte) ([]byte, error) {
	if c.network == nil {
		return nil, fmt.Errorf("ключ DEAL не установлен")
	}
	return c.network.DecryptBlock(block)
}

// DEALKeyExpander генерирует 64-битные DES-ключи с помощью DES-CBC
// с фиксированным ключом 0123456789ABCDEF и нулевым начальным состоянием.
// После первого прохода по частям исходного ключа добавляются константы
// 8000000000000000, 4000000000000000, 2000000000000000, 1000000000000000.
type DEALKeyExpander struct{}

func (DEALKeyExpander) ExpandKey(key []byte) ([][]byte, error) {
	rounds, err := roundsForKey(len(key))
	if err != nil {
		return nil, err
	}
	des := point4.NewDESCipher()
	if err := des.SetKey([]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}); err != nil {
		return nil, err
	}
	parts := len(key) / point4.BlockSize
	previous := make([]byte, point4.BlockSize)
	keys := make([][]byte, rounds)
	for i := range keys {
		start := (i % parts) * point4.BlockSize
		input := append([]byte(nil), key[start:start+point4.BlockSize]...)
		if i >= parts {
			input[0] ^= byte(0x80 >> uint(i-parts))
		}
		for j := range input {
			input[j] ^= previous[j]
		}
		keys[i], err = des.EncryptBlock(input)
		if err != nil {
			return nil, fmt.Errorf("ключ раунда DEAL %d: %w", i+1, err)
		}
		previous = keys[i]
	}
	return keys, nil
}

// DESAdapter превращает полный DES в раундовую функцию F(R, K) = DES_K(R).
// Собственный экземпляр DES в каждом вызове исключает общий изменяемый ключ
// при параллельной обработке блоков контекстом из пункта 2.
type DESAdapter struct{}

func (DESAdapter) Transform(block, roundKey []byte) ([]byte, error) {
	if len(block) != point4.BlockSize || len(roundKey) != point4.BlockSize {
		return nil, fmt.Errorf("F DEAL требует блок и ключ по 8 байт")
	}
	des := point4.NewDESCipher()
	if err := des.SetKey(roundKey); err != nil {
		return nil, err
	}
	return des.EncryptBlock(block)
}
