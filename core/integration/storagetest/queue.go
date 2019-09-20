package storagetest

import (
	"context"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"github.com/google/keytransparency/core/adminserver"
	"github.com/google/keytransparency/core/keyserver"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// Queuer writes items to the queue.
type Queuer interface {
	keyserver.MutationLogs
	adminserver.LogsAdmin
}

type QueueStorageFactory func(ctx context.Context, t *testing.T, dirID string, logIDs ...int64) Queuer

type QueueStorageTest func(ctx context.Context, t *testing.T, f QueueStorageFactory)

// RunQueueStorageTests runs all the batch storage tests against the provided map storage implementation.
func RunQueueStorageTests(t *testing.T, factory QueueStorageFactory) {
	ctx := context.Background()
	b := &QueueTests{}
	for name, f := range map[string]QueueStorageTest{
		// TODO(gbelvin): Discover test methods via reflection.
		"TestSetWritable": b.TestSetWritable,
		"TestReadLog":     b.TestReadLog,
	} {
		t.Run(name, func(t *testing.T) { f(ctx, t, factory) })
	}
}

// QueueTests is a suite of tests to run against
type QueueTests struct{}

func (QueueTests) TestSetWritable(ctx context.Context, t *testing.T, f QueueStorageFactory) {
	directoryID := "TestSetWritable"
	for _, tc := range []struct {
		desc       string
		logIDs     []int64
		set        map[int64]bool
		wantLogIDs []int64
		wantCode   codes.Code
	}{
		{desc: "one row", logIDs: []int64{10}, wantLogIDs: []int64{10}},
		{desc: "one row disabled", logIDs: []int64{10}, set: map[int64]bool{10: false}, wantCode: codes.NotFound},
		{desc: "one row enabled", logIDs: []int64{1, 2, 3}, set: map[int64]bool{1: false, 2: false}, wantLogIDs: []int64{3}},
		{desc: "multi", logIDs: []int64{1, 2, 3}, set: map[int64]bool{1: true, 2: false}, wantLogIDs: []int64{1, 3}},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			m := f(ctx, t, directoryID, tc.logIDs...)
			wantLogs := make(map[int64]bool)
			for _, logID := range tc.wantLogIDs {
				wantLogs[logID] = true
			}

			for logID, enabled := range tc.set {
				if err := m.SetWritable(ctx, directoryID, logID, enabled); err != nil {
					t.Errorf("SetWritable(): %v", err)
				}
			}

			logIDs, err := m.ListLogs(ctx, directoryID, true /* Only Writable */)
			if status.Code(err) != tc.wantCode {
				t.Errorf("ListLogs(): %v, want %v", err, tc.wantCode)
			}
			if err != nil {
				return
			}
			logs := make(map[int64]bool)
			for _, log := range logIDs {
				logs[log] = true
			}
			if got, want := logs, wantLogs; !cmp.Equal(got, want) {
				t.Errorf("randLog(): %v, want %v", got, want)
			}
		})
	}
}

func mustMarshal(t *testing.T, p proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(p)
	if err != nil {
		t.Fatalf("proto.Marshal(): %v", err)
	}
	return b
}

func (QueueTests) TestReadLog(ctx context.Context, t *testing.T, newForTest QueueStorageFactory) {
	directoryID := "TestReadLog"
	logID := int64(5)
	m := newForTest(ctx, t, directoryID, logID)
	for i := byte(0); i < 10; i++ {
		entry := &pb.EntryUpdate{Mutation: &pb.SignedEntry{Entry: mustMarshal(t, &pb.Entry{Index: []byte{i}})}}
		if _, err := m.Send(ctx, directoryID, entry, entry, entry); err != nil {
			t.Fatalf("Send(): %v", err)
		}
	}

	for _, tc := range []struct {
		batchSize int32
		count     int
	}{
		{batchSize: 0, count: 0},
		{batchSize: 1, count: 3},
		{batchSize: 4, count: 6},
		{batchSize: 100, count: 30},
	} {
		rows, err := m.ReadLog(ctx, directoryID, logID, 0, time.Now().UnixNano(), tc.batchSize)
		if err != nil {
			t.Fatalf("ReadLog(%v): %v", tc.batchSize, err)
		}
		if got, want := len(rows), tc.count; got != want {
			t.Fatalf("ReadLog(%v): len: %v, want %v", tc.batchSize, got, want)
		}
	}
}
