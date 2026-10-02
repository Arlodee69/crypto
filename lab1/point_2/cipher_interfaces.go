package point2

// KeyExpander описывает генерацию раундовых ключей (пункт 2.1).
// Каждый элемент результата — отдельный раундовый ключ.
type KeyExpander interface {
	ExpandKey(key []byte) ([][]byte, error)
}

// RoundTransformer описывает шифрующее преобразование (пункт 2.2).
type RoundTransformer interface {
	Transform(block, roundKey []byte) ([]byte, error)
}

// SymmetricCipher описывает блочный шифр с преднастроенными ключами (пункт 2.3).
// EncryptBlock и DecryptBlock должны возвращать новый блок размера BlockSize,
// не изменять аргументы и поддерживать одновременные вызовы из разных goroutine.
// SetKey вызывается до начала обработки данных, а не одновременно с ней.
type SymmetricCipher interface {
	SetKey(key []byte) error
	BlockSize() int
	EncryptBlock(block []byte) ([]byte, error)
	DecryptBlock(block []byte) ([]byte, error)
}
