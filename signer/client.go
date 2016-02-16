package signer

import (
	"errors"

	"github.com/google/e2e-key-server/db"
	"golang.org/x/net/context"
)

type Client struct {
	distributed db.Distributed
}

func NewClient(distributed db.Distributed) *Client {
	return &Client{distributed}
}

// QueuMutation takes a mutation that has already been verified, stores it in
// the mutations table and equques the mutation for the mapper to process.
func (c *Client) QueueMutation(ctx context.Context, index, mutation []byte) error {
	// If entry does not exist, insert it, otherwise update.
	// return c.distributed.WriteMutation(ctx, index, mutation)
	return errors.New("Not implemented")
}
