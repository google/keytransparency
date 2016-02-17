package memtree

import (
	"github.com/google/e2e-key-server/db"

	"golang.org/x/net/context"
)

type MemTree struct {
	db db.Mapper
}

func New(db db.Mapper) *MemTree {
	return &MemTree{db}
}

func (m *MemTree) ReadLeaf(ctx context.Context, index []byte) ([]byte, error) {
	return m.db.ReadLeaf(ctx, index)
}
func (m *MemTree) WriteLeaf(ctx context.Context, index, leaf []byte) error {
	return m.db.WriteLeaf(ctx, index, leaf)
}
