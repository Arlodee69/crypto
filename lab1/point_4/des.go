package point4

import (
	"encoding/binary"
	"fmt"

	point1 "cryptography/lab1/point_1"
	point2 "cryptography/lab1/point_2"
	point3 "cryptography/lab1/point_3"
)

const BlockSize = 8
const Rounds = 16

type DESCipher struct{ network *point3.FeistelCipher }

var _ point2.SymmetricCipher = (*DESCipher)(nil)
var _ point2.KeyExpander = DESKeyExpander{}
var _ point2.RoundTransformer = DESRoundTransformer{}

func NewDESCipher() *DESCipher {
	network, err := point3.NewFeistelCipher(BlockSize, Rounds, DESKeyExpander{}, DESRoundTransformer{})
	if err != nil {
		panic(err)
	}
	return &DESCipher{network: network}
}

func (c *DESCipher) SetKey(key []byte) error {
	if c.network == nil {
		return fmt.Errorf("DES должен быть создан через NewDESCipher")
	}
	return c.network.SetKey(key)
}

func (c *DESCipher) BlockSize() int                            { return BlockSize }
func (c *DESCipher) EncryptBlock(block []byte) ([]byte, error) { return c.transform(block, false) }
func (c *DESCipher) DecryptBlock(block []byte) ([]byte, error) { return c.transform(block, true) }

func (c *DESCipher) transform(block []byte, decrypt bool) ([]byte, error) {
	if c.network == nil {
		return nil, fmt.Errorf("DES должен быть создан через NewDESCipher")
	}
	if len(block) != BlockSize {
		return nil, fmt.Errorf("длина блока DES должна быть 8 байт, получено %d", len(block))
	}
	permuted, err := permute(block, initialPermutation[:])
	if err != nil {
		return nil, err
	}
	var result []byte
	if decrypt {
		result, err = c.network.DecryptBlock(permuted)
	} else {
		result, err = c.network.EncryptBlock(permuted)
	}
	if err != nil {
		return nil, err
	}
	return permute(result, finalPermutation[:])
}

func permute(value []byte, table []int) ([]byte, error) {
	return point1.Permute(value, table, point1.MostSignificantFirst, 1)
}

type DESKeyExpander struct{}

func (DESKeyExpander) ExpandKey(key []byte) ([][]byte, error) {
	if len(key) != 8 {
		return nil, fmt.Errorf("длина ключа DES должна быть 8 байт, получено %d", len(key))
	}
	selected, err := permute(key, keyPermutation[:])
	if err != nil {
		return nil, err
	}
	var value uint64
	for _, b := range selected {
		value = value<<8 | uint64(b)
	}
	left, right := uint32(value>>28), uint32(value&0xfffffff)
	keys := make([][]byte, Rounds)
	for i, shift := range keyShifts {
		left = ((left << shift) | (left >> (28 - shift))) & 0xfffffff
		right = ((right << shift) | (right >> (28 - shift))) & 0xfffffff
		var packed [8]byte
		binary.BigEndian.PutUint64(packed[:], (uint64(left)<<28|uint64(right))<<8)
		keys[i], err = permute(packed[:7], compressionPermutation[:])
		if err != nil {
			return nil, err
		}
	}
	return keys, nil
}

type DESRoundTransformer struct{}

func (DESRoundTransformer) Transform(block, roundKey []byte) ([]byte, error) {
	if len(block) != 4 || len(roundKey) != 6 {
		return nil, fmt.Errorf("F DES требует блок 4 байта и ключ 6 байт")
	}
	expanded, err := permute(block, expansionPermutation[:])
	if err != nil {
		return nil, err
	}
	var value uint64
	for i, b := range expanded {
		value = value<<8 | uint64(b^roundKey[i])
	}
	var substituted uint32
	for i := 0; i < 8; i++ {
		group := byte(value>>uint(42-6*i)) & 0x3f
		row := (group&0x20)>>4 | group&1
		column := (group >> 1) & 0xf
		substituted = substituted<<4 | uint32(sBoxes[i][row][column])
	}
	var packed [4]byte
	binary.BigEndian.PutUint32(packed[:], substituted)
	return permute(packed[:], roundPermutation[:])
}
