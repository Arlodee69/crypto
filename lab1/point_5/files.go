package point5

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	point2 "cryptography/lab1/point_2"
)

func TestFiles(ctx context.Context, cipher point2.SymmetricCipher, key []byte, outputDir string, paths []string, log io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if log == nil {
		log = io.Discard
	}
	inputs := filepath.Join(outputDir, "inputs")
	if err := os.MkdirAll(inputs, 0755); err != nil {
		return err
	}
	files, err := createSamples(inputs)
	if err != nil {
		return err
	}
	files = append(files, paths...)

	for _, mode := range modes {
		for _, padding := range paddings {
			resultDir := filepath.Join(outputDir, mode.name, padding.name)
			decryptedDir := filepath.Join(resultDir, "decrypted")
			if err := os.MkdirAll(decryptedDir, 0755); err != nil {
				return err
			}

			for i, source := range files {
				if err := ctx.Err(); err != nil {
					return err
				}
				c, err := point2.NewCipherContext(cipher, key, mode.mode, padding.padding, nil, point2.WithWorkers(4))
				if err != nil {
					return err
				}
				name := fmt.Sprintf("%02d-%s", i, filepath.Base(source))
				encryptedPath := filepath.Join(resultDir, name+".enc")
				restoredPath := filepath.Join(decryptedDir, name)

				if err := <-c.EncryptFile(ctx, source, encryptedPath); err != nil {
					return err
				}
				if err := <-c.DecryptFile(ctx, encryptedPath, restoredPath); err != nil {
					return err
				}
				equal, err := filesEqual(ctx, source, restoredPath)
				if err != nil {
					return err
				}
				if !equal {
					return fmt.Errorf("%s/%s: файл %s восстановлен неверно", mode.name, padding.name, source)
				}
				fmt.Fprintf(log, "%s/%s: %s — OK\n", mode.name, padding.name, source)
			}
		}
	}
	return nil
}

func filesEqual(ctx context.Context, first, second string) (bool, error) {
	a, err := os.Open(first)
	if err != nil {
		return false, err
	}
	defer a.Close()
	b, err := os.Open(second)
	if err != nil {
		return false, err
	}
	defer b.Close()
	left, right := make([]byte, 64*1024), make([]byte, 64*1024)
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		n, e1 := io.ReadFull(a, left)
		m, e2 := io.ReadFull(b, right)
		if e1 != nil && e1 != io.EOF && e1 != io.ErrUnexpectedEOF {
			return false, e1
		}
		if e2 != nil && e2 != io.EOF && e2 != io.ErrUnexpectedEOF {
			return false, e2
		}
		if n != m || !bytes.Equal(left[:n], right[:m]) {
			return false, nil
		}
		if e1 != nil || e2 != nil {
			return e1 == e2, nil
		}
	}
}
