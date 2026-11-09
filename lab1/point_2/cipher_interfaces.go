package point2

type KeyExpander interface {
	ExpandKey(key []byte) ([][]byte, error)
}

type RoundTransformer interface {
	Transform(block, roundKey []byte) ([]byte, error)
}

type SymmetricCipher interface {
	SetKey(key []byte) error
	BlockSize() int
	EncryptBlock(block []byte) ([]byte, error)
	DecryptBlock(block []byte) ([]byte, error)
}
