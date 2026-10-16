// Package point7 демонстрирует DEAL на массивах и файлах во всех режимах.
package point7

import (
	"context"
	"fmt"
	"io"

	"cryptography/lab1/point_2"
	"cryptography/lab1/point_5"
	"cryptography/lab1/point_6"
)

// Run проверяет DEAL-128. RunWithKey позволяет выбрать любую длину ключа DEAL.
func Run(ctx context.Context, outputDir string, paths []string, log io.Writer) (string, error) {
	return RunWithKey(ctx, outputDir, paths, log, []byte("0123456789abcdef"))
}

func RunWithKey(ctx context.Context, outputDir string, paths []string, log io.Writer, key []byte) (string, error) {
	if _, err := (point6.DEALKeyExpander{}).ExpandKey(key); err != nil {
		return "", err
	}
	return point5.RunWithCipher(ctx, outputDir, paths, log, point5.DemoCipher{
		Name:      fmt.Sprintf("DEAL-%d", len(key)*8),
		Extension: "deal", DirectoryPrefix: "deal-demo-",
		Key: append([]byte(nil), key...),
		New: func() point2.SymmetricCipher { return point6.NewDEALCipher() },
	})
}
