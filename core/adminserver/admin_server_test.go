// Copyright 2017 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package adminserver

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/golang/protobuf/ptypes"
	"github.com/google/keytransparency/core/directory"
	"github.com/google/keytransparency/core/fake"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/storage/testdb"
	"github.com/google/trillian/testonly"
	"github.com/google/trillian/testonly/integration"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tpb "github.com/google/trillian"

	_ "github.com/google/trillian/crypto/keys/der/proto" // Register PrivateKey ProtoHandler
	_ "github.com/google/trillian/merkle/coniks"         // Register hasher
	_ "github.com/google/trillian/merkle/rfc6962"        // Register hasher
)

func vrfKeyGen(ctx context.Context, spec *keyspb.Specification) (proto.Message, error) {
	return der.NewProtoFromSpec(spec)
}

type miniEnv struct {
	ms             *testonly.MockServer
	srv            *Server
	stopMockServer func()
	stopController func()
}

func newMiniEnv(ctx context.Context, t *testing.T) (*miniEnv, error) {
	fakeDirectories := fake.NewDirectoryStorage()
	dir := &directory.Directory{DirectoryID: "existingdirectory"}
	if err := fakeDirectories.Write(ctx, dir); err != nil {
		return nil, fmt.Errorf("admin.Write(): %v", err)
	}

	ctrl := gomock.NewController(t)
	s, stopFakeServer, err := testonly.NewMockServer(ctrl)
	if err != nil {
		return nil, fmt.Errorf("error starting fake server: %v", err)
	}
	srv := New(s.LogClient, s.MapClient, s.AdminClient, s.AdminClient, fakeDirectories, nil, fakeBatcher{}, vrfKeyGen)

	return &miniEnv{
		ms:             s,
		srv:            srv,
		stopController: ctrl.Finish,
		stopMockServer: stopFakeServer,
	}, nil
}

func (e *miniEnv) Close() {
	e.stopController()
	e.stopMockServer()
}

type fakeQueueAdmin struct{}

func (fakeQueueAdmin) AddLogs(_ context.Context, _ string, _ ...int64) error          { return nil }
func (fakeQueueAdmin) SetWritable(_ context.Context, _ string, _ int64, _ bool) error { return nil }
func (fakeQueueAdmin) ListLogs(_ context.Context, _ string, _ bool) ([]int64, error)  { return nil, nil }

type fakeBatcher struct{}

func (fakeBatcher) WriteBatchSources(_ context.Context, _ string, _ int64, _ *spb.MapMetadata) error {
	return nil
}

func TestCreateDirectory(t *testing.T) {
	for _, tc := range []struct {
		desc        string
		directoryID string
		wantCode    codes.Code
		expect      func(*miniEnv)
	}{
		{
			desc:        "Already Exists",
			directoryID: "existingdirectory",
			wantCode:    codes.AlreadyExists,
			expect:      func(e *miniEnv) {},
		},
		{
			desc:        "Create map fails",
			directoryID: "mapinitfails",
			wantCode:    codes.Internal,
			expect: func(e *miniEnv) {
				e.ms.Admin.EXPECT().CreateTree(gomock.Any(), gomock.Any()).Return(&tpb.Tree{TreeType: tpb.TreeType_PREORDERED_LOG}, nil)
				e.ms.Log.EXPECT().InitLog(gomock.Any(), gomock.Any()).Return(&tpb.InitLogResponse{}, nil)
				e.ms.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(&tpb.GetLatestSignedLogRootResponse{}, nil)
				e.ms.Admin.EXPECT().CreateTree(gomock.Any(), gomock.Any()).Return(&tpb.Tree{TreeType: tpb.TreeType_MAP}, nil)
				e.ms.Map.EXPECT().InitMap(gomock.Any(), gomock.Any()).Return(&tpb.InitMapResponse{}, nil)
				e.ms.Map.EXPECT().GetSignedMapRootByRevision(gomock.Any(), gomock.Any()).
					Return(&tpb.GetSignedMapRootResponse{}, status.Errorf(codes.FailedPrecondition, "tree needs init")).MinTimes(1)
			},
		},
		{
			desc:        "log init with map root fails",
			directoryID: "initfails",
			wantCode:    codes.Internal,
			expect: func(e *miniEnv) {
				e.ms.Admin.EXPECT().CreateTree(gomock.Any(), gomock.Any()).Return(&tpb.Tree{TreeType: tpb.TreeType_PREORDERED_LOG}, nil)
				e.ms.Log.EXPECT().InitLog(gomock.Any(), gomock.Any()).Return(&tpb.InitLogResponse{}, nil)
				e.ms.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(&tpb.GetLatestSignedLogRootResponse{}, nil)
				e.ms.Admin.EXPECT().CreateTree(gomock.Any(), gomock.Any()).Return(&tpb.Tree{TreeType: tpb.TreeType_MAP}, nil)
				e.ms.Map.EXPECT().InitMap(gomock.Any(), gomock.Any()).Return(&tpb.InitMapResponse{}, nil)
				e.ms.Map.EXPECT().GetSignedMapRootByRevision(gomock.Any(), gomock.Any()).
					Return(&tpb.GetSignedMapRootResponse{}, nil).MinTimes(1)
				// Verify that we delete the log and map when the sequencer's init fails.
				// In this case the sequencer's init fails because it can't create a verifier for a fake tree. HashStrategy is UNKNOWN.
				e.ms.Admin.EXPECT().DeleteTree(gomock.Any(), gomock.Any()).Return(&tpb.Tree{}, nil).MinTimes(2)
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			e, err := newMiniEnv(ctx, t)
			if err != nil {
				t.Fatalf("newMiniEnv(): %v", err)
			}
			defer e.Close()

			tc.expect(e)

			if _, err := e.srv.CreateDirectory(ctx, &pb.CreateDirectoryRequest{
				DirectoryId: tc.directoryID,
				MinInterval: ptypes.DurationProto(60 * time.Hour),
				MaxInterval: ptypes.DurationProto(60 * time.Hour),
			}); status.Code(err) != tc.wantCode {
				t.Errorf("CreateDirectory(): %v, want %v", err, tc.wantCode)
			}
		})
	}
}

func TestCreateRead(t *testing.T) {
	testdb.SkipIfNoMySQL(t)
	ctx := context.Background()
	storage := fake.NewDirectoryStorage()

	// Map server
	mapEnv, err := integration.NewMapEnv(ctx, false)
	if err != nil {
		t.Fatalf("Failed to create trillian map server: %v", err)
	}

	// Log server
	numSequencers := 1
	unused := ""
	logEnv, err := integration.NewLogEnv(ctx, numSequencers, unused)
	if err != nil {
		t.Fatalf("Failed to create trillian log server: %v", err)
	}

	svr := New(logEnv.Log, mapEnv.Map, logEnv.Admin, mapEnv.Admin, storage, fakeQueueAdmin{}, fakeBatcher{}, vrfKeyGen)

	for _, tc := range []struct {
		directoryID              string
		minInterval, maxInterval time.Duration
	}{
		{
			directoryID: "testdirectory",
			minInterval: 1 * time.Second,
			maxInterval: 5 * time.Second,
		},
	} {
		_, err := svr.CreateDirectory(ctx, &pb.CreateDirectoryRequest{
			DirectoryId: tc.directoryID,
			MinInterval: ptypes.DurationProto(tc.minInterval),
			MaxInterval: ptypes.DurationProto(tc.maxInterval),
		})
		if err != nil {
			t.Fatalf("CreateDirectory(): %v", err)
		}
		directory, err := svr.GetDirectory(ctx, &pb.GetDirectoryRequest{DirectoryId: tc.directoryID})
		if err != nil {
			t.Fatalf("GetDirectory(): %v", err)
		}
		if got, want := directory.Log.TreeType, tpb.TreeType_PREORDERED_LOG; got != want {
			t.Errorf("Log.TreeType: %v, want %v", got, want)
		}
		if got, want := directory.Map.TreeType, tpb.TreeType_MAP; got != want {
			t.Errorf("Map.TreeType: %v, want %v", got, want)
		}
	}
}

func TestDelete(t *testing.T) {
	testdb.SkipIfNoMySQL(t)
	ctx := context.Background()
	storage := fake.NewDirectoryStorage()

	// Map server
	mapEnv, err := integration.NewMapEnv(ctx, false)
	if err != nil {
		t.Fatalf("Failed to create trillian map server: %v", err)
	}

	// Log server
	numSequencers := 1
	unused := ""
	logEnv, err := integration.NewLogEnv(ctx, numSequencers, unused)
	if err != nil {
		t.Fatalf("Failed to create trillian log server: %v", err)
	}

	svr := New(logEnv.Log, mapEnv.Map, logEnv.Admin, mapEnv.Admin, storage, fakeQueueAdmin{}, fakeBatcher{}, vrfKeyGen)

	for _, tc := range []struct {
		directoryID              string
		minInterval, maxInterval time.Duration
	}{
		{
			directoryID: "testdirectory",
			minInterval: 1 * time.Second,
			maxInterval: 5 * time.Second,
		},
	} {
		if _, err := svr.CreateDirectory(ctx, &pb.CreateDirectoryRequest{
			DirectoryId: tc.directoryID,
			MinInterval: ptypes.DurationProto(tc.minInterval),
			MaxInterval: ptypes.DurationProto(tc.maxInterval),
		}); err != nil {
			t.Fatalf("CreateDirectory(): %v", err)
		}
		if _, err := svr.DeleteDirectory(ctx, &pb.DeleteDirectoryRequest{DirectoryId: tc.directoryID}); err != nil {
			t.Fatalf("DeleteDirectory(): %v", err)
		}
		if _, err := svr.GarbageCollect(ctx, &pb.GarbageCollectRequest{
			Before: ptypes.TimestampNow(),
		}); err != nil {
			t.Fatalf("GarbageCollect(): %v", err)
		}
		_, err = svr.GetDirectory(ctx, &pb.GetDirectoryRequest{DirectoryId: tc.directoryID, ShowDeleted: true})
		if got, want := status.Code(err), codes.NotFound; got != want {
			t.Fatalf("GetDirectory(): %v, want %v", got, want)
		}
	}
}

func TestListDirectories(t *testing.T) {
	testdb.SkipIfNoMySQL(t)
	ctx := context.Background()
	storage := fake.NewDirectoryStorage()

	// Map server
	mapEnv, err := integration.NewMapEnv(ctx, false)
	if err != nil {
		t.Fatalf("Failed to create trillian map server: %v", err)
	}

	// Log server
	numSequencers := 1
	unused := ""
	logEnv, err := integration.NewLogEnv(ctx, numSequencers, unused)
	if err != nil {
		t.Fatalf("Failed to create trillian log server: %v", err)
	}

	svr := New(logEnv.Log, mapEnv.Map, logEnv.Admin, mapEnv.Admin, storage, fakeQueueAdmin{}, fakeBatcher{}, vrfKeyGen)

	for _, tc := range []struct {
		directoryIDs []string
	}{
		{
			directoryIDs: []string{"A", "B"},
		},
	} {
		for _, directory := range tc.directoryIDs {
			if _, err := svr.CreateDirectory(ctx, &pb.CreateDirectoryRequest{
				DirectoryId: directory,
				MinInterval: ptypes.DurationProto(60 * time.Hour),
				MaxInterval: ptypes.DurationProto(60 * time.Hour),
			}); err != nil {
				t.Fatalf("CreateDirectory(%v): %v", directory, err)
			}
		}
		resp, err := svr.ListDirectories(ctx, &pb.ListDirectoriesRequest{})
		if err != nil {
			t.Fatalf("ListDirectories(): %v", err)
		}
		// Make sure we got all the same directories back.
		want := make(map[string]bool)
		for _, d := range tc.directoryIDs {
			want[d] = true
		}
		for _, d := range resp.GetDirectories() {
			directoryID := d.GetDirectoryId()
			if ok := want[directoryID]; !ok {
				t.Errorf("Did not find directory %v in list response", directoryID)
			}
		}
	}
}
