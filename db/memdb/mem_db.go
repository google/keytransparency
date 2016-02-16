package memdb

import (
	"crypto/sha512"

	"golang.org/x/net/context"
)

const IndexSize = sha512.Size256

type MemDB struct {
	queue  chan []byte
	leaves map[[IndexSize]byte][]byte
}

// Create creates a storage object from an existing db connection.
func New() *MemDB {
	return &MemDB{
		queue:  make(chan []byte),
		leaves: make(map[[IndexSize]byte][]byte),
	}
}

func (d *MemDB) QueueMutation(ctx context.Context, index, mutation []byte) error {
	d.queue <- mutation
	return nil
}

func (d *MemDB) Queue() <-chan []byte {
	return d.queue
}
