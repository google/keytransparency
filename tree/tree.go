package tree

import (
	"golang.org/x/net/context"
)

// Sparse is a sparse merkle tree
type Sparse interface {
	ReadRoot(ctx context.Context) ([]byte, error)
	ReadLeaf(ctx context.Context, index []byte) ([]byte, error)
	WriteLeaf(ctx context.Context, index, leaf []byte) error
	Neighbors(ctx context.Context, index []byte) ([][]byte, error)
}

// SparseHist is a temporal sparse merkle tree
type SparseHist interface {
	Sparse
	WriteLeafAt(ctx context.Context, index, leaf []byte, epoch int64) error
	NeighborsAt(ctx context.Context, epoch int64, index []byte) ([][]byte, error)
}
