package point5

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"

	point2 "cryptography/lab1/point_2"
	point4 "cryptography/lab1/point_4"
)

var modes = []struct {
	mode point2.CipherMode
	name string
}{
	{point2.ECB, "ECB"}, {point2.CBC, "CBC"}, {point2.PCBC, "PCBC"},
	{point2.CFB, "CFB"}, {point2.OFB, "OFB"}, {point2.CTR, "CTR"}, {point2.RandomDelta, "RandomDelta"},
}
var paddings = []struct {
	padding point2.PaddingMode
	name    string
}{
	{point2.Zeros, "Zeros"}, {point2.ANSIX923, "ANSIX923"}, {point2.PKCS7, "PKCS7"}, {point2.ISO10126, "ISO10126"},
}

func TestBytes(ctx context.Context, cipher point2.SymmetricCipher, key []byte, log io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if log == nil {
		log = io.Discard
	}

	rng := rand.New(rand.NewSource(42))
	blockSize := cipher.BlockSize()
	arrays := make([][]byte, 0, 8)
	for _, size := range []int{0, 1, blockSize - 1, blockSize, blockSize + 1, 31, 64, 1025} {
		data := make([]byte, size)
		if _, err := rng.Read(data); err != nil {
			return err
		}
		arrays = append(arrays, data)
	}

	for _, mode := range modes {
		for _, padding := range paddings {
			for _, data := range arrays {
				c, err := point2.NewCipherContext(cipher, key, mode.mode, padding.padding, nil, point2.WithWorkers(4))
				if err != nil {
					return err
				}

				encrypted := <-c.Encrypt(ctx, data)
				if encrypted.Err != nil {
					return encrypted.Err
				}
				decrypted := <-c.Decrypt(ctx, encrypted.Data, len(data))
				if decrypted.Err != nil {
					return decrypted.Err
				}

				if !bytes.Equal(data, decrypted.Data) {
					return fmt.Errorf("%s/%s: массив %d байт восстановлен неверно", mode.name, padding.name, len(data))
				}
			}
			fmt.Fprintf(log, "%s/%s: %d массивов — OK\n", mode.name, padding.name, len(arrays))
		}
	}
	return nil
}

func RunBytes(ctx context.Context) (string, error) {
	data := []byte{0x00, 0x00}
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1}
	c, err := point2.NewCipherContext(point4.NewDESCipher(), key, point2.CFB, point2.Zeros, nil)
	if err != nil {
		return "", err
	}

	encrypted := <-c.Encrypt(ctx, data)
	if encrypted.Err != nil {
		return "", encrypted.Err
	}
	decrypted := <-c.Decrypt(ctx, encrypted.Data, len(data))
	if decrypted.Err != nil {
		return "", decrypted.Err
	}
	if !bytes.Equal(data, decrypted.Data) {
		return "", fmt.Errorf("CFB/Zeros: массив восстановлен неверно")
	}
	return "массив восстановлен верно", nil
}
