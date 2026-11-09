package point7

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	point5 "cryptography/lab1/point_5"
	point6 "cryptography/lab1/point_6"
)

func TestDEALBytes(t *testing.T) {
	for _, size := range []int{16, 24, 32} {
		t.Run(fmt.Sprintf("key-%d", size*8), func(t *testing.T) {
			key := bytes.Repeat([]byte{0x42}, size)
			if err := point5.TestBytes(context.Background(), point6.NewDEALCipher(), key, io.Discard); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDEALFiles(t *testing.T) {
	for _, size := range []int{16, 24, 32} {
		t.Run(fmt.Sprintf("key-%d", size*8), func(t *testing.T) {
			key := bytes.Repeat([]byte{0x42}, size)
			dir := t.TempDir()
			source := filepath.Join(dir, "custom.bin")
			original := []byte{0, 255, 1, 0, 0}
			if err := os.WriteFile(source, original, 0600); err != nil {
				t.Fatal(err)
			}
			if err := point5.TestFiles(context.Background(), point6.NewDEALCipher(), key, dir, []string{source}, io.Discard); err != nil {
				t.Fatal(err)
			}
			restored, err := filepath.Glob(filepath.Join(dir, "*", "*", "decrypted", "*"))
			if err != nil || len(restored) != 196 {
				t.Fatalf("восстановлено %d файлов вместо 196; err=%v", len(restored), err)
			}
			unchanged, err := os.ReadFile(source)
			if err != nil || !bytes.Equal(unchanged, original) {
				t.Fatal("исходный файл изменён")
			}
		})
	}
}
