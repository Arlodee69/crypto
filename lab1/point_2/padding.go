package point2

import (
	"crypto/rand"
	"fmt"
)

type PaddingMode uint8

const (
	Zeros PaddingMode = iota
	ANSIX923
	PKCS7
	ISO10126
)

func addPadding(data []byte, blockSize int, mode PaddingMode) ([]byte, error) {
	count := blockSize - len(data)%blockSize
	if mode == Zeros && count == blockSize {
		count = 0
	}
	result := make([]byte, len(data)+count)
	copy(result, data)
	if count == 0 {
		return result, nil
	}
	switch mode {
	case Zeros:
	case ANSIX923:
		result[len(result)-1] = byte(count)
	case PKCS7:
		for i := len(data); i < len(result); i++ {
			result[i] = byte(count)
		}
	case ISO10126:
		if _, err := rand.Read(result[len(data) : len(result)-1]); err != nil {
			return nil, fmt.Errorf("генерация набивки: %w", err)
		}
		result[len(result)-1] = byte(count)
	default:
		return nil, fmt.Errorf("неизвестный режим набивки: %d", mode)
	}
	return result, nil
}

func removePadding(data []byte, blockSize int, mode PaddingMode, originalLength ...int) ([]byte, error) {
	if len(data)%blockSize != 0 {
		return nil, fmt.Errorf("длина данных не кратна размеру блока")
	}
	if mode == Zeros {
		if len(originalLength) != 1 {
			return nil, fmt.Errorf("для снятия Zeros нужна исходная длина")
		}
		length := originalLength[0]
		if length < 0 || length > len(data) || len(data)-length >= blockSize {
			return nil, fmt.Errorf("недопустимая исходная длина для Zeros: %d", length)
		}
		if !allZero(data[length:]) {
			return nil, fmt.Errorf("повреждена набивка Zeros")
		}
		return data[:length], nil
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("отсутствует блок с набивкой")
	}
	count := int(data[len(data)-1])
	if count < 1 || count > blockSize || count > len(data) {
		return nil, fmt.Errorf("недопустимая длина набивки: %d", count)
	}
	for i := len(data) - count; i < len(data)-1; i++ {
		switch mode {
		case ANSIX923:
			if data[i] != 0 {
				return nil, fmt.Errorf("повреждена набивка ANSI X.923")
			}
		case PKCS7:
			if data[i] != byte(count) {
				return nil, fmt.Errorf("повреждена набивка PKCS7")
			}
		}
	}
	return data[:len(data)-count], nil
}
