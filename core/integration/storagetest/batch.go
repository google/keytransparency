package storagetest

import (
	"context"
	"testing"

	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Batcher writes batch definitions to storage.
type Batcher interface {
	// WriteBatchSources saves the (low, high] boundaries used for each log in making this revision.
	WriteBatchSources(ctx context.Context, dirID string, rev int64, meta *spb.MapMetadata) error
	// ReadBatch returns the batch definitions for a given revision.
	ReadBatch(ctx context.Context, directoryID string, rev int64) (*spb.MapMetadata, error)
	// HighestRev returns the highest defined revision number for directoryID.
	HighestRev(ctx context.Context, directoryID string) (int64, error)
}

type BatchStorageFactory func(ctx context.Context, t *testing.T) Batcher

type BatchStorageTest func(ctx context.Context, t *testing.T, b Batcher)

// RunBatchStorageTests runs all the batch storage tests against the provided map storage implementation.
func RunBatchStorageTests(t *testing.T, storageFactory BatchStorageFactory) {
	ctx := context.Background()
	b := &BatchTests{}
	for name, f := range map[string]BatchStorageTest{
		"TestNotFound": b.TestNotFound,
	} {
		ms := storageFactory(ctx, t)
		t.Run(name, func(t *testing.T) { f(ctx, t, ms) })
	}
}

// BatchTests is a suite of tests to run against
type BatchTests struct{}

func (*BatchTests) TestNotFound(ctx context.Context, t *testing.T, b Batcher) {
	_, err := b.ReadBatch(ctx, "nodir", 0)
	st := status.Convert(err)
	if got, want := st.Code(), codes.NotFound; got != want {
		t.Errorf("ReadBatch(): %v, want %v", err, want)
	}
}
