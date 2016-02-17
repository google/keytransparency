package tree

import (
	"golang.org/x/net/context"
)

type Sparse interface {
	ReadLeaf(ctx context.Context, index []byte) ([]byte, error)
	WriteLeaf(ctx context.Context, index, leaf []byte) error
}
