package point2

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
)

// CipherMode задаёт режим работы блочного шифра.
type CipherMode uint8

const (
	ECB CipherMode = iota
	CBC
	PCBC
	CFB
	OFB
	CTR
	RandomDelta
)

type contextOptions struct {
	workers int
	delta   []byte
}

// ContextOption задаёт дополнительный параметр конструктора (пункт 2.4).
type ContextOption func(*contextOptions) error

// WithWorkers ограничивает число параллельно обрабатываемых блоков.
func WithWorkers(workers int) ContextOption {
	return func(options *contextOptions) error {
		if workers < 1 {
			return fmt.Errorf("число обработчиков должно быть положительным")
		}
		options.workers = workers
		return nil
	}
}

// WithDelta задаёт ненулевой шаг счётчика для Random Delta.
// Если шаг не задан, конструктор генерирует случайный нечётный шаг.
func WithDelta(delta []byte) ContextOption {
	copyOfDelta := append([]byte(nil), delta...)
	return func(options *contextOptions) error {
		if len(copyOfDelta) == 0 {
			return fmt.Errorf("шаг Random Delta не должен быть пустым")
		}
		options.delta = append([]byte(nil), copyOfDelta...)
		return nil
	}
}

// CipherResult содержит результат асинхронного преобразования.
type CipherResult struct {
	Data []byte
	Err  error
}

// CipherContext объединяет шифр, режим, набивку и параметры (пункт 2.4).
// Переданный шифр принадлежит контексту: после создания нельзя менять его ключ
// или передавать его другому контексту. Сам контекст допускает параллельные операции.
type CipherContext struct {
	cipher    SymmetricCipher
	mode      CipherMode
	padding   PaddingMode
	blockSize int
	iv        []byte
	delta     []byte
	workers   int
}

// NewCipherContext настраивает шифр ключом. iv необязателен (nil): для режимов,
// кроме ECB, тогда генерируется случайный вектор длиной BlockSize.
// Для дешифрования нужно передать тот же IV и, для Random Delta, тот же Delta.
// В CTR и Random Delta счётчик трактуется как целое big-endian; шаги равны
// соответственно 1 и Delta, сложение выполняется по модулю 2^(8*BlockSize).
func NewCipherContext(cipher SymmetricCipher, key []byte, mode CipherMode, padding PaddingMode, iv []byte, options ...ContextOption) (*CipherContext, error) {
	if cipher == nil || isNilCipher(cipher) {
		return nil, fmt.Errorf("шифр не должен быть nil")
	}
	if mode > RandomDelta {
		return nil, fmt.Errorf("неизвестный режим шифрования: %d", mode)
	}
	if padding > ISO10126 {
		return nil, fmt.Errorf("неизвестный режим набивки: %d", padding)
	}
	blockSize := cipher.BlockSize()
	if blockSize < 1 || (padding != Zeros && blockSize > 255) {
		return nil, fmt.Errorf("недопустимый размер блока для выбранной набивки: %d", blockSize)
	}
	settings := contextOptions{workers: runtime.GOMAXPROCS(0)}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("дополнительный параметр не должен быть nil")
		}
		if err := option(&settings); err != nil {
			return nil, err
		}
	}
	if settings.delta != nil && mode != RandomDelta {
		return nil, fmt.Errorf("Delta применима только к Random Delta")
	}
	initial := append([]byte(nil), iv...)
	if mode == ECB {
		if len(iv) != 0 {
			return nil, fmt.Errorf("ECB не использует вектор инициализации")
		}
	} else if iv == nil {
		initial = make([]byte, blockSize)
		if _, err := rand.Read(initial); err != nil {
			return nil, fmt.Errorf("генерация IV: %w", err)
		}
	} else if len(initial) != blockSize {
		return nil, fmt.Errorf("длина IV должна быть %d байт", blockSize)
	}
	if mode == RandomDelta {
		if settings.delta == nil {
			settings.delta = make([]byte, blockSize)
			if _, err := rand.Read(settings.delta); err != nil {
				return nil, fmt.Errorf("генерация Delta: %w", err)
			}
			settings.delta[blockSize-1] |= 1 // делаем нечетным, чтобы были все возможные значения счетчика
		}
		if len(settings.delta) != blockSize || allZero(settings.delta) {
			return nil, fmt.Errorf("Delta должна быть ненулевым массивом из %d байт", blockSize)
		}
	}
	if err := cipher.SetKey(append([]byte(nil), key...)); err != nil {
		return nil, fmt.Errorf("настройка ключа: %w", err)
	}
	return &CipherContext{cipher: cipher, mode: mode, padding: padding,
		blockSize: blockSize, iv: initial, delta: settings.delta, workers: settings.workers}, nil
}

func isNilCipher(cipher SymmetricCipher) bool {
	value := reflect.ValueOf(cipher)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func allZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

// IV возвращает копию вектора инициализации для сохранения вместе с шифротекстом.
func (c *CipherContext) IV() []byte { return append([]byte(nil), c.iv...) }

// Delta возвращает копию шага Random Delta для последующего дешифрования.
func (c *CipherContext) Delta() []byte { return append([]byte(nil), c.delta...) }

// Encrypt запускает шифрование и возвращает канал с одним результатом.
// Входной массив копируется до запуска goroutine; канал затем закрывается.
func (c *CipherContext) Encrypt(ctx context.Context, data []byte) <-chan CipherResult {
	return c.launch(ctx, data, false)
}

// Decrypt запускает дешифрование и удаление набивки.
func (c *CipherContext) Decrypt(ctx context.Context, data []byte) <-chan CipherResult {
	return c.launch(ctx, data, true)
}

func (c *CipherContext) launch(ctx context.Context, data []byte, decrypt bool) <-chan CipherResult {
	input := append([]byte(nil), data...)
	result := make(chan CipherResult, 1)
	if ctx == nil {
		ctx = context.Background()
	}
	go func() {
		defer close(result)
		output, err := c.process(ctx, input, decrypt)
		result <- CipherResult{Data: output, Err: err}
	}()
	return result
}

// EncryptInto записывает результат в переменную по ссылке.
// Читать или изменять destination можно только после получения результата из канала.
func (c *CipherContext) EncryptInto(ctx context.Context, data []byte, destination *[]byte) <-chan error {
	return c.into(ctx, data, destination, false)
}

// DecryptInto — вариант дешифрования с записью результата по ссылке.
func (c *CipherContext) DecryptInto(ctx context.Context, data []byte, destination *[]byte) <-chan error {
	return c.into(ctx, data, destination, true)
}

func (c *CipherContext) into(ctx context.Context, data []byte, destination *[]byte, decrypt bool) <-chan error {
	finished := make(chan error, 1)
	if destination == nil {
		finished <- fmt.Errorf("ссылка на результат не должна быть nil")
		close(finished)
		return finished
	}
	operation := c.launch(ctx, data, decrypt)
	go func() {
		defer close(finished)
		result := <-operation
		if result.Err == nil {
			*destination = result.Data
		}
		finished <- result.Err
	}()
	return finished
}

// EncryptFile асинхронно шифрует файл. Файл целиком загружается в память.
func (c *CipherContext) EncryptFile(ctx context.Context, inputPath, outputPath string) <-chan error {
	return c.file(ctx, inputPath, outputPath, false)
}

// DecryptFile асинхронно дешифрует файл.
func (c *CipherContext) DecryptFile(ctx context.Context, inputPath, outputPath string) <-chan error {
	return c.file(ctx, inputPath, outputPath, true)
}

func (c *CipherContext) file(ctx context.Context, inputPath, outputPath string, decrypt bool) <-chan error {
	finished := make(chan error, 1)
	if ctx == nil {
		ctx = context.Background()
	}
	go func() {
		defer close(finished)
		finished <- c.processFile(ctx, inputPath, outputPath, decrypt)
	}()
	return finished
}

func (c *CipherContext) processFile(ctx context.Context, inputPath, outputPath string, decrypt bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	input, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("чтение файла: %w", err)
	}
	output, err := c.process(ctx, input, decrypt)
	if err != nil {
		return err
	}
	// До успешного преобразования и записи во временный файл результат не меняется.
	temporary, err := os.CreateTemp(filepath.Dir(outputPath), ".lab1-*")
	if err != nil {
		return fmt.Errorf("создание файла: %w", err)
	}
	defer os.Remove(temporary.Name())
	_, writeErr := temporary.Write(output)
	closeErr := temporary.Close()
	if writeErr != nil {
		return fmt.Errorf("запись файла: %w", writeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(temporary.Name(), outputPath); err != nil {
		return fmt.Errorf("сохранение результата: %w", err)
	}
	return nil
}

func (c *CipherContext) process(ctx context.Context, data []byte, decrypt bool) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if decrypt {
		if len(data)%c.blockSize != 0 {
			return nil, fmt.Errorf("длина шифротекста не кратна размеру блока")
		}
	} else {
		var err error
		data, err = addPadding(data, c.blockSize, c.padding)
		if err != nil {
			return nil, err
		}
	}
	output, err := c.transform(ctx, data, decrypt)
	if err != nil {
		return nil, err
	}
	if decrypt {
		return removePadding(output, c.blockSize, c.padding)
	}
	return output, nil
}
