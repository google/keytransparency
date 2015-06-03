// Package storage provides an API to persistant storage, implemented with spanner.
package storage

import (
	"time"

	context "golang.org/x/net/context"
	keyspb "github.com/google/key-server-transparency/proto/v2"
)

type BasicStorage interface {
	// InsertLogTableRow ensures that there is a valid directory entry for our data.
	InsertLogTableRow(ctx context.Context)
	// UpdateKey updates a UserKey row. Fails if the row does not already exist.
	UpdateKey(ctx context.Context, signedKey *keyspb.SignedKey, vuf []byte) error
	// InsertKey inserts a new UserKey row. Fails if the row already exists.
	InsertKey(ctx context.Context, signedKey *keyspb.SignedKey, vuf []byte) error
	// DeleteKey deletes a key.
	DeleteKey(ctx context.Context, vuf []byte) error
	// ReadKey reads a key.
	ReadKey(ctx context.Context, vuf []byte) (*keyspb.SignedKey, error)
}

type ConiksStorage interface {
	// InsertLogTableRow ensures that there is a valid directory entry for our data.
	InsertLogTableRow(ctx context.Context)

	ReadProof(ctx context.Context, vuf []byte) (*keyspb.Proof, error)
	ReadHistoricProof(ctx context.Context, vuf []byte, epoch time.Time) (*keyspb.Proof, error)
	ReadKeys(ctx context.Context, vuf []byte) ([]*keyspb.SignedKey, error)
	ReadHistoricKeys(ctx context.Context, vuf []byte, epoch time.Time) ([]*keyspb.SignedKey, error)
	ReadKeyPromisess(ctx context.Context, vuf []byte) ([]*keyspb.SignedKey, error)

	// InsertKey inserts a new UserKey row. Fails if the row already exists.
	InsertKeyPromise(ctx context.Context, signedKey *keyspb.SignedKey, vuf []byte) error
	// UpdateKey updates a UserKey row. Fails if the row does not already exist.
	UpdateKeyPromise(ctx context.Context, signedKey *keyspb.SignedKey, vuf []byte, keyid string) error
	// DeleteKey deletes a key.
	DeleteKeyPromise(ctx context.Context, vuf []byte, keyid string) error
}
