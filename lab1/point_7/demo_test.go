package point7

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Один сценарий для всех длин ключа: все режимы/набивки, массивы и файлы.
func TestDEALDemo(t *testing.T) {
	for _, size := range []int{16, 24, 32} {
		t.Run(fmt.Sprintf("DEAL-%d", size*8), func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "custom.bin")
			original := []byte{0, 255, 1, 0, 0}
			if err := os.WriteFile(source, original, 0600); err != nil {
				t.Fatal(err)
			}
			var log bytes.Buffer
			dir, err := RunWithKey(context.Background(), root, []string{source}, &log, bytes.Repeat([]byte{0x42}, size))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(log.String(), "массивов — OK") != 7*4 {
				t.Fatal("проверены не все сочетания режимов и набивок")
			}
			files, err := filepath.Glob(filepath.Join(dir, "*", "*", "*.restored"))
			if err != nil || len(files) != 7*3*7 {
				t.Fatalf("файлов %d вместо 147; err=%v", len(files), err)
			}
			unchanged, err := os.ReadFile(source)
			if err != nil || !bytes.Equal(unchanged, original) {
				t.Fatal("исходный файл изменён")
			}
		})
	}
}

func TestDEALDemoCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, t.TempDir(), nil, nil); err != context.Canceled {
		t.Fatalf("err=%v", err)
	}
}
