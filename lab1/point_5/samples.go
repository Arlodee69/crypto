package point5

import (
	_ "embed"
	"encoding/binary"
	"os"
	"path/filepath"
)

// Здесь только подготовка образцов, шифрования в этом файле нет.
//
//go:embed assets/landscape.jpg
var samplePicture []byte

func createSamples(dir string) ([]string, error) {
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
	video := []byte("YUV4MPEG2 W2 H2 F25:1 Ip A1:1 C420jpeg\nFRAME\n")
	video = append(video, 16, 80, 160, 235, 128, 128)
	video = append(video, []byte("FRAME\n")...)
	video = append(video, 235, 160, 80, 16, 128, 128)
	samples := []struct {
		name string
		data []byte
	}{
		{"text.txt", []byte("Лабораторная работа 1: DES, шифрование и дешифрование.\n")},
		{"landscape.jpg", samplePicture}, {"tone.wav", audio}, {"video.y4m", video},
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
