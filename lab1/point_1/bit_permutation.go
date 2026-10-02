package point1

import "fmt"

type BitOrder uint8

const (
	MostSignificantFirst BitOrder = iota
	LeastSignificantFirst
)

// MSB: [0,1,2,3,4,5,6,7], [8,9,10,11,12,13,14,15];
// LSB: [15,14,13,12,11,10,9,8], [7,6,5,4,3,2,1,0].

func Permute(value []byte, pBlock []int, bitOrder BitOrder, firstBitNumber int) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("исходное значение не должно быть nil")
	}
	if pBlock == nil {
		return nil, fmt.Errorf("P-блок не должен быть nil")
	}
	if bitOrder != MostSignificantFirst && bitOrder != LeastSignificantFirst {
		return nil, fmt.Errorf("недопустимое направление нумерации: %d", bitOrder)
	}
	if firstBitNumber != 0 && firstBitNumber != 1 {
		return nil, fmt.Errorf("номер первого бита должен быть 0 или 1")
	}

	outputByteCount := len(pBlock) / 8
	if len(pBlock)%8 != 0 {
		outputByteCount++
	}
	result := make([]byte, outputByteCount)

	for outputIndex, bitNumber := range pBlock {
		if bitNumber < firstBitNumber {
			return nil, fmt.Errorf("P-блок содержит недопустимый номер бита %d в позиции %d", bitNumber, outputIndex)
		}
		inputIndex := bitNumber - firstBitNumber
		inputByteIndex := inputIndex / 8
		if inputByteIndex >= len(value) {
			return nil, fmt.Errorf("P-блок содержит недопустимый номер бита %d в позиции %d", bitNumber, outputIndex)
		}

		inputBitOffset := inputIndex % 8
		outputByteIndex := outputIndex / 8
		outputBitOffset := outputIndex % 8
		if bitOrder == MostSignificantFirst {
			inputBitOffset = 7 - inputBitOffset
			outputBitOffset = 7 - outputBitOffset
		} else {
			inputByteIndex = len(value) - 1 - inputByteIndex
			outputByteIndex = len(result) - 1 - outputByteIndex
		}

		bit := (value[inputByteIndex] >> uint(inputBitOffset)) & 1
		result[outputByteIndex] |= bit << uint(outputBitOffset)
	}

	return result, nil
}
