package point2

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

const fileChunkSize = 64 * 1024

const zerosFileMagic = "ZR01"

func (c *CipherContext) processStream(ctx context.Context, input io.Reader, output io.Writer, decrypt bool, originalLength int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.padding == Zeros {
		var header [12]byte
		if decrypt {
			if _, err := io.ReadFull(input, header[:]); err != nil {
				return fmt.Errorf("чтение заголовка Zeros: %w", err)
			}
			if string(header[:4]) != zerosFileMagic {
				return fmt.Errorf("неизвестный формат файла Zeros")
			}
			length := binary.BigEndian.Uint64(header[4:])
			if length > uint64(1<<63-1) {
				return fmt.Errorf("недопустимая длина в заголовке Zeros")
			}
			originalLength = int64(length)
		} else {
			if originalLength < 0 {
				return fmt.Errorf("неизвестна исходная длина файла Zeros")
			}
			copy(header[:4], zerosFileMagic)
			binary.BigEndian.PutUint64(header[4:], uint64(originalLength))
			if err := writeChunk(output, header[:]); err != nil {
				return err
			}
		}
	}

	chunkSize := fileChunkSize / c.blockSize * c.blockSize
	if chunkSize == 0 {
		chunkSize = c.blockSize
	}
	buffer := make([]byte, chunkSize)
	state := c.newModeState()
	var pending []byte // Последний расшифрованный блок до снятия набивки.
	var consumed, written int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := io.ReadFull(input, buffer)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return fmt.Errorf("чтение файла: %w", readErr)
		}
		consumed += int64(n)
		final := readErr != nil
		data := buffer[:n]
		if decrypt {
			if n%c.blockSize != 0 {
				return fmt.Errorf("длина шифротекста не кратна размеру блока")
			}
		} else if final {
			var err error
			data, err = addPadding(data, c.blockSize, c.padding)
			if err != nil {
				return err
			}
		}
		if len(data) > 0 {
			transformed, err := c.transformChunk(ctx, data, decrypt, state)
			if err != nil {
				return err
			}
			if decrypt {
				if err := writeChunk(output, pending); err != nil {
					return err
				}
				written += int64(len(pending))
				end := len(transformed) - c.blockSize
				if err := writeChunk(output, transformed[:end]); err != nil {
					return err
				}
				written += int64(end)
				pending = append(pending[:0], transformed[end:]...)
			} else if err := writeChunk(output, transformed); err != nil {
				return err
			}
		}
		if !final {
			continue
		}
		if decrypt {
			var lengths []int
			if c.padding == Zeros {
				remaining := originalLength - written
				if remaining < 0 || remaining > int64(len(pending)) {
					return fmt.Errorf("длина файла не соответствует заголовку Zeros")
				}
				lengths = []int{int(remaining)}
			}
			last, err := removePadding(pending, c.blockSize, c.padding, lengths...)
			if err != nil {
				return err
			}
			if err := writeChunk(output, last); err != nil {
				return err
			}
		} else if c.padding == Zeros && consumed != originalLength {
			return fmt.Errorf("размер исходного файла изменился во время чтения")
		}
		return ctx.Err()
	}
}

func writeChunk(output io.Writer, data []byte) error {
	n, err := output.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return err
}
