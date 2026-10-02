package point5

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestDemo(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "custom.bin")
	data := []byte{0, 255, 1, 0, 0}
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	dir, err := Run(context.Background(), root, []string{source}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	// Run уже сравнивает содержимое каждого восстановленного файла.
	files, err := filepath.Glob(filepath.Join(dir, "*", "*", "*.restored"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 7*3*7 {
		t.Fatalf("восстановлено %d файлов, ожидалось 147", len(files))
	}
	unchanged, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != string(data) {
		t.Fatal("исходный файл изменён")
	}
}

func TestDemoCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, t.TempDir(), nil, nil); err != context.Canceled {
		t.Fatalf("err=%v", err)
	}
}
