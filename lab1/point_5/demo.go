// Package point5 демонстрирует DES через асинхронный контекст пункта 2.
package point5

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"math/rand"
	"os"
	"path/filepath"

	"cryptography/lab1/point_2"
	"cryptography/lab1/point_4"
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

// Run создаёт отдельный каталог запуска внутри outputDir и проверяет точное
// восстановление массивов и файлов. Дополнительные paths могут содержать файлы
// любого формата. Исходные файлы читаются, результаты остаются в каталоге запуска.
// Возвращаемый путь позволяет найти результаты и при ошибке.
func Run(ctx context.Context, outputDir string, paths []string, log io.Writer) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if log == nil {
		log = io.Discard
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(outputDir, "des-demo-")
	if err != nil {
		return "", err
	}
	if err := run(ctx, dir, paths, log); err != nil {
		return dir, err
	}
	return dir, nil
}

func run(ctx context.Context, dir string, paths []string, log io.Writer) error {
	inputs := filepath.Join(dir, "inputs")
	if err := os.Mkdir(inputs, 0755); err != nil {
		return err
	}
	generated, err := createSamples(inputs)
	if err != nil {
		return err
	}
	files := append(generated, paths...)
	rng := rand.New(rand.NewSource(42)) // Воспроизводимые псевдослучайные входные данные.
	arrays := make([][]byte, 0, 8)
	for _, size := range []int{0, 1, 7, 8, 9, 31, 64, 1025} {
		data := make([]byte, size)
		if _, err := rng.Read(data); err != nil {
			return err
		}
		// Zeros не сохраняет концевые нули; для этого примера последний байт ненулевой.
		if size > 0 {
			data[size-1] = 1
		}
		arrays = append(arrays, data)
	}
	for _, mode := range modes {
		for _, padding := range paddings {
			if err := ctx.Err(); err != nil {
				return err
			}
			newContext := func() (*point2.CipherContext, error) {
				return point2.NewCipherContext(point4.NewDESCipher(), []byte{0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1}, mode.mode, padding.padding, nil, point2.WithWorkers(4))
			}
			for _, data := range arrays {
				c, err := newContext()
				if err != nil {
					return err
				}
				encrypted := <-c.Encrypt(ctx, data)
				if encrypted.Err != nil {
					return encrypted.Err
				}
				decrypted := <-c.Decrypt(ctx, encrypted.Data)
				if decrypted.Err != nil {
					return decrypted.Err
				}
				if !bytes.Equal(data, decrypted.Data) {
					return fmt.Errorf("%s/%s: массив %d байт восстановлен неверно", mode.name, padding.name, len(data))
				}
			}
			fmt.Fprintf(log, "%s/%s: %d массивов — OK\n", mode.name, padding.name, len(arrays))
			// Для произвольных файлов нужны набивки, сохраняющие концевые нули.
			if padding.padding == point2.Zeros {
				continue
			}
			resultDir := filepath.Join(dir, mode.name, padding.name)
			if err := os.MkdirAll(resultDir, 0755); err != nil {
				return err
			}
			for i, source := range files {
				if err := ctx.Err(); err != nil {
					return err
				}
				original, err := os.ReadFile(source)
				if err != nil {
					return fmt.Errorf("чтение %s: %w", source, err)
				}
				c, err := newContext()
				if err != nil {
					return err
				}
				name := fmt.Sprintf("%02d-%s", i, filepath.Base(source))
				encryptedPath := filepath.Join(resultDir, name+".des")
				restoredPath := filepath.Join(resultDir, name+".restored")
				if err := <-c.EncryptFile(ctx, source, encryptedPath); err != nil {
					return err
				}
				// Параметры позволяют повторить дешифрование вне текущего запуска.
				metadata, err := json.MarshalIndent(struct {
					Key     string             `json:"demo_key_hex"`
					IV      string             `json:"iv_hex"`
					Delta   string             `json:"delta_hex"`
					Mode    point2.CipherMode  `json:"mode"`
					Padding point2.PaddingMode `json:"padding"`
				}{"133457799bbcdff1", hex.EncodeToString(c.IV()), hex.EncodeToString(c.Delta()), mode.mode, padding.padding}, "", "  ")
				if err != nil {
					return err
				}
				if err := os.WriteFile(encryptedPath+".json", metadata, 0600); err != nil {
					return err
				}
				if err := <-c.DecryptFile(ctx, encryptedPath, restoredPath); err != nil {
					return err
				}
				restored, err := os.ReadFile(restoredPath)
				if err != nil {
					return err
				}
				if !bytes.Equal(original, restored) {
					return fmt.Errorf("%s/%s: файл %s восстановлен неверно", mode.name, padding.name, source)
				}
				fmt.Fprintf(log, "  %s: %d байт — OK\n", source, len(original))
			}
		}
	}
	return nil
}

// Небольшие валидные образцы не требуют внешних файлов или медиабиблиотек.
func createSamples(dir string) ([]string, error) {
	var picture bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			img.Set(x, y, color.RGBA{uint8(x * 32), uint8(y * 32), 128, 255})
		}
	}
	if err := png.Encode(&picture, img); err != nil {
		return nil, err
	}
	// WAV: PCM mono, 8 kHz, 8 бит, короткий прямоугольный тон.
	audio := make([]byte, 44+800)
	copy(audio, "RIFF")
	binary.LittleEndian.PutUint32(audio[4:], uint32(len(audio)-8))
	copy(audio[8:], "WAVEfmt ")
	binary.LittleEndian.PutUint32(audio[16:], 16)
	binary.LittleEndian.PutUint16(audio[20:], 1)
	binary.LittleEndian.PutUint16(audio[22:], 1)
	binary.LittleEndian.PutUint32(audio[24:], 8000)
	binary.LittleEndian.PutUint32(audio[28:], 8000)
	binary.LittleEndian.PutUint16(audio[32:], 1)
	binary.LittleEndian.PutUint16(audio[34:], 8)
	copy(audio[36:], "data")
	binary.LittleEndian.PutUint32(audio[40:], 800)
	for i := 44; i < len(audio); i++ {
		audio[i] = 96
		if (i-44)%20 < 10 {
			audio[i] = 160
		}
	}
	// YUV4MPEG2: два кадра 2x2, planar YUV 4:2:0, 25 кадров/с.
	video := []byte("YUV4MPEG2 W2 H2 F25:1 Ip A1:1 C420jpeg\nFRAME\n")
	video = append(video, 16, 80, 160, 235, 128, 128)
	video = append(video, []byte("FRAME\n")...)
	video = append(video, 235, 160, 80, 16, 128, 128)
	samples := []struct {
		name string
		data []byte
	}{
		{"text.txt", []byte("Лабораторная работа 1: DES, шифрование и дешифрование.\n")},
		{"image.png", picture.Bytes()}, {"tone.wav", audio}, {"video.y4m", video},
		{"source_test.go", []byte("package sample\n\nimport \"testing\"\n\nfunc TestSum(t *testing.T) {\n\tif 2+2 != 4 { t.Fatal(\"sum\") }\n}\n")},
		{"trailing-zero.bin", []byte{1, 2, 3, 0, 0, 0}},
	}
	paths := make([]string, 0, len(samples))
	for _, sample := range samples {
		path := filepath.Join(dir, sample.name)
		if err := os.WriteFile(path, sample.data, 0600); err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return paths, nil
}
