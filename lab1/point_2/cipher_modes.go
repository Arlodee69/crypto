package point2

import (
	"context"
	"fmt"
	"sync"
)

func (c *CipherContext) transform(ctx context.Context, data []byte, decrypt bool) ([]byte, error) {
	return c.transformChunk(ctx, data, decrypt, c.newModeState())
}

type modeState struct {
	feedback []byte
	counter  []byte
}

func (c *CipherContext) newModeState() *modeState {
	return &modeState{feedback: append([]byte(nil), c.iv...), counter: append([]byte(nil), c.iv...)}
}

func (c *CipherContext) transformChunk(ctx context.Context, data []byte, decrypt bool, state *modeState) ([]byte, error) {
	output := make([]byte, len(data))
	blocks := len(data) / c.blockSize
	if c.mode == ECB || c.mode == CTR || c.mode == RandomDelta ||
		(decrypt && (c.mode == CBC || c.mode == CFB)) {
		err := parallelBlocks(ctx, blocks, c.workers, func(index int) error {
			start := index * c.blockSize
			input := data[start : start+c.blockSize]
			var result []byte
			var err error
			switch c.mode {
			case ECB:
				result, err = c.block(input, decrypt)
			case CBC:
				result, err = c.block(input, true)
				if err == nil {
					previous := state.feedback
					if index > 0 {
						previous = data[start-c.blockSize : start]
					}
					result = xorBytes(result, previous)
				}
			case CFB:
				previous := state.feedback
				if index > 0 {
					previous = data[start-c.blockSize : start]
				}
				result, err = c.block(previous, false)
				if err == nil {
					result = xorBytes(input, result)
				}
			case CTR, RandomDelta:
				step := c.delta
				if c.mode == CTR {
					step = make([]byte, c.blockSize)
					step[c.blockSize-1] = 1
				}
				counter := counterAt(state.counter, step, index)
				result, err = c.block(counter, false)
				if err == nil {
					result = xorBytes(input, result)
				}
			}
			if err != nil {
				return fmt.Errorf("блок %d: %w", index, err)
			}
			copy(output[start:start+c.blockSize], result)
			return nil
		})
		if err != nil {
			return nil, err
		}
		if blocks > 0 && (c.mode == CBC || c.mode == CFB) {
			state.feedback = append(state.feedback[:0], data[len(data)-c.blockSize:]...)
		}
		if c.mode == CTR || c.mode == RandomDelta {
			step := c.delta
			if c.mode == CTR {
				step = make([]byte, c.blockSize)
				step[c.blockSize-1] = 1
			}
			state.counter = counterAt(state.counter, step, blocks)
		}
		return output, nil
	}

	feedback := state.feedback
	for index := 0; index < blocks; index++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		start := index * c.blockSize
		input := data[start : start+c.blockSize]
		var result []byte
		var err error
		switch c.mode {
		case CBC:
			result, err = c.block(xorBytes(input, feedback), false)
			feedback = result
		case PCBC:
			if decrypt {
				result, err = c.block(input, true)
				if err == nil {
					result = xorBytes(result, feedback)
				}
			} else {
				result, err = c.block(xorBytes(input, feedback), false)
			}
			if err == nil {
				feedback = xorBytes(input, result)
			}
		case CFB:
			result, err = c.block(feedback, false)
			if err == nil {
				result = xorBytes(input, result)
				feedback = result
			}
		case OFB:
			feedback, err = c.block(feedback, false)
			if err == nil {
				result = xorBytes(input, feedback)
			}
		default:
			return nil, fmt.Errorf("неизвестный режим шифрования: %d", c.mode)
		}
		if err != nil {
			return nil, fmt.Errorf("блок %d: %w", index, err)
		}
		copy(output[start:start+c.blockSize], result)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state.feedback = feedback
	return output, nil
}

func (c *CipherContext) block(input []byte, decrypt bool) ([]byte, error) {
	var result []byte
	var err error
	if decrypt {
		result, err = c.cipher.DecryptBlock(input)
	} else {
		result, err = c.cipher.EncryptBlock(input)
	}
	if err != nil {
		return nil, err
	}
	if len(result) != c.blockSize {
		return nil, fmt.Errorf("шифр вернул блок длиной %d вместо %d", len(result), c.blockSize)
	}
	return result, nil
}

func xorBytes(left, right []byte) []byte {
	result := make([]byte, len(left))
	for i := range left {
		result[i] = left[i] ^ right[i]
	}
	return result
}

func addCounter(destination, step []byte) {
	carry := 0
	for i := len(destination) - 1; i >= 0; i-- {
		sum := int(destination[i]) + int(step[i]) + carry
		destination[i] = byte(sum)
		carry = sum >> 8
	}
}

func counterAt(iv, step []byte, index int) []byte {
	result := append([]byte(nil), iv...)
	multiple := append([]byte(nil), step...)
	for index > 0 {
		if index&1 != 0 {
			addCounter(result, multiple)
		}
		addCounter(multiple, multiple)
		index >>= 1
	}
	return result
}

func parallelBlocks(ctx context.Context, count, workers int, operation func(int) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if workers > count {
		workers = count
	}
	jobs := make(chan int)
	var group sync.WaitGroup
	var firstError error
	var once sync.Once
	for i := 0; i < workers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				if ctx.Err() != nil {
					return
				}
				if err := operation(index); err != nil {
					once.Do(func() { firstError = err; cancel() })
					return
				}
			}
		}()
	}
dispatch:
	for index := 0; index < count; index++ {
		select {
		case <-ctx.Done():
			break dispatch
		case jobs <- index:
		}
	}
	close(jobs)
	group.Wait()
	if firstError != nil {
		return firstError
	}
	return ctx.Err()
}
