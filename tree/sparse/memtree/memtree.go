package memtree

import (
	"crypto/sha512"

	"golang.org/x/net/context"
)

const IndexSize = sha512.Size256

type MemTree struct {
	leaves map[[IndexSize]byte][]byte
	nodes  map[[IndexSize]byte][]byte
}

func New() *MemTree {
	return &MemTree{
		leaves: make(map[[IndexSize]byte][]byte),
		nodes:  make(map[[IndexSize]byte][]byte),
	}
}

func (m *MemTree) ReadLeaf(ctx context.Context, index []byte) ([]byte, error) {
	var k [IndexSize]byte
	copy(k[:], index[:IndexSize])
	return m.leaves[k], nil
}
func (m *MemTree) WriteLeaf(ctx context.Context, index, leaf []byte) error {
	var k [IndexSize]byte
	copy(k[:], index[:IndexSize])
	m.leaves[k] = leaf
	return nil
}
func (m *MemTree) ReadRoot(ctx context.Context) ([]byte, error) {
	return []byte(""), nil
}
