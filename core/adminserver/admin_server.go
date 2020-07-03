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

// Package adminserver contains the KeyTransparencyAdmin implementation
package adminserver

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"github.com/google/keytransparency/core/directory"
	"github.com/google/trillian/client"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/crypto/sigpb"
	"github.com/google/trillian/types"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
)

const (
	maxDisplayNameLength = 20
)

var (
	logArgs = &tpb.CreateTreeRequest{
		Tree: &tpb.Tree{
			TreeState: tpb.TreeState_ACTIVE,
			TreeType:  tpb.TreeType_PREORDERED_LOG,
			// Clients that verify output from the log need to import
			// _ "github.com/google/trillian/merkle/rfc6962"
			HashStrategy:       tpb.HashStrategy_RFC6962_SHA256,
			SignatureAlgorithm: sigpb.DigitallySigned_ECDSA,
			HashAlgorithm:      sigpb.DigitallySigned_SHA256,
			MaxRootDuration:    ptypes.DurationProto(0 * time.Millisecond),
		},
	}
	mapArgs = &tpb.CreateTreeRequest{
		Tree: &tpb.Tree{
			TreeState: tpb.TreeState_ACTIVE,
			TreeType:  tpb.TreeType_MAP,
			// Clients that verify output from the map need to import
			// _ "github.com/google/trillian/merkle/coniks"
			HashStrategy:       tpb.HashStrategy_CONIKS_SHA256,
			SignatureAlgorithm: sigpb.DigitallySigned_ECDSA,
			HashAlgorithm:      sigpb.DigitallySigned_SHA256,
			MaxRootDuration:    ptypes.DurationProto(0 * time.Millisecond),
		},
	}
	keyspec = &keyspb.Specification{
		Params: &keyspb.Specification_EcdsaParams{
			EcdsaParams: &keyspb.Specification_ECDSA{
				Curve: keyspb.Specification_ECDSA_P256,
			},
		},
	}
)

// LogsAdmin controls the lifecycle and scaling of mutation logs.
type LogsAdmin interface {
	// AddLogs creates and adds new logs for writing to a directory.
	AddLogs(ctx context.Context, directoryID string, logIDs ...int64) error
	// SetWritable enables or disables new writes from going to logID.
	SetWritable(ctx context.Context, directoryID string, logID int64, enabled bool) error
	// ListLogs returns a list of logs, optionally filtered by the writable bit.
	ListLogs(ctx context.Context, directoryID string, writable bool) ([]int64, error)
}

// Batcher writes batch definitions to storage.
type Batcher interface {
	// WriteBatchSources saves the (low, high] boundaries used for each log in making this revision.
	WriteBatchSources(ctx context.Context, dirID string, rev int64, meta *spb.MapMetadata) error
}

var _ pb.KeyTransparencyAdminServer = &Server{} // Ensure *Server satisfies the AdminServer interface.

// Server implements pb.KeyTransparencyAdminServer
type Server struct {
	tlog        tpb.TrillianLogClient
	tmap        tpb.TrillianMapClient
	logAdmin    tpb.TrillianAdminClient
	mapAdmin    tpb.TrillianAdminClient
	directories directory.Storage
	logsAdmin   LogsAdmin
	batcher     Batcher
	keygen      keys.ProtoGenerator
}

// New returns a KeyTransparencyAdmin implementation.
func New(
	tlog tpb.TrillianLogClient,
	tmap tpb.TrillianMapClient,
	logAdmin, mapAdmin tpb.TrillianAdminClient,
	directories directory.Storage,
	logsAdmin LogsAdmin,
	batcher Batcher,
	keygen keys.ProtoGenerator,
) *Server {
	return &Server{
		tlog:        tlog,
		tmap:        tmap,
		logAdmin:    logAdmin,
		mapAdmin:    mapAdmin,
		directories: directories,
		logsAdmin:   logsAdmin,
		batcher:     batcher,
		keygen:      keygen,
	}
}

// ListDirectories produces a list of the configured directories
func (s *Server) ListDirectories(ctx context.Context, in *pb.ListDirectoriesRequest) (
	*pb.ListDirectoriesResponse, error) {
	directories, err := s.directories.List(ctx, in.GetShowDeleted())
	if err != nil {
		return nil, err
	}

	resp := []*pb.Directory{}
	for _, d := range directories {
		info, err := s.fetchDirectory(ctx, d)
		if err != nil {
			return nil, err
		}
		resp = append(resp, info)
	}
	return &pb.ListDirectoriesResponse{Directories: resp}, nil
}

// fetchDirectory converts an adminstorage.Directory object into a pb.Directory object
// by fetching the relevant info from Trillian.
func (s *Server) fetchDirectory(ctx context.Context, d *directory.Directory) (*pb.Directory, error) {
	return &pb.Directory{
		DirectoryId: d.DirectoryID,
		Log:         d.Log,
		Map:         d.Map,
		Vrf:         d.VRF,
		MinInterval: ptypes.DurationProto(d.MinInterval),
		MaxInterval: ptypes.DurationProto(d.MaxInterval),
		Deleted:     d.Deleted,
	}, nil
}

func trimTree(t *tpb.Tree) *tpb.Tree {
	return &tpb.Tree{
		TreeId:             t.TreeId,
		TreeType:           t.TreeType,
		PublicKey:          t.PublicKey,
		HashStrategy:       t.HashStrategy,
		HashAlgorithm:      t.HashAlgorithm,
		SignatureAlgorithm: t.SignatureAlgorithm,
	}
}

// GetDirectory retrieves the directory info for a given directory.
func (s *Server) GetDirectory(ctx context.Context, in *pb.GetDirectoryRequest) (*pb.Directory, error) {
	directory, err := s.directories.Read(ctx, in.GetDirectoryId(), in.GetShowDeleted())
	if err != nil {
		return nil, err
	}
	return s.fetchDirectory(ctx, directory)
}

// privKeyOrGen returns the message inside privKey if privKey is not nil,
// otherwise, it generates a new key with keygen.
func privKeyOrGen(ctx context.Context, privKey *any.Any, keygen keys.ProtoGenerator) (proto.Message, error) {
	if privKey != nil {
		var keyProto ptypes.DynamicAny
		if err := ptypes.UnmarshalAny(privKey, &keyProto); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to unmarshal privatekey: %v", err)
		}
		return keyProto.Message, nil
	}
	return keygen(ctx, keyspec)
}

// treeConfig returns a CreateTreeRequest
// - with a set PrivateKey is not nil, otherwise KeySpec is set.
// - with a tree description of "KT directory %v"
func treeConfig(treeTemplate *tpb.CreateTreeRequest, privKey *any.Any, directoryID string) *tpb.CreateTreeRequest {
	config := proto.Clone(treeTemplate).(*tpb.CreateTreeRequest)

	if privKey != nil {
		config.Tree.PrivateKey = privKey
	} else {
		config.KeySpec = keyspec
	}

	config.Tree.Description = fmt.Sprintf("KT directory %s", directoryID)
	config.Tree.DisplayName = directoryID
	if len(directoryID) >= maxDisplayNameLength {
		config.Tree.DisplayName = directoryID[:maxDisplayNameLength]
	}
	return config
}

// CreateDirectory reachs out to Trillian to produce new trees.
func (s *Server) CreateDirectory(ctx context.Context, in *pb.CreateDirectoryRequest) (*pb.Directory, error) {
	glog.Infof("Begin CreateDirectory(%v)", in.GetDirectoryId())
	if _, err := s.directories.Read(ctx, in.GetDirectoryId(), true); status.Code(err) != codes.NotFound {
		// Directory already exists.
		return nil, status.Errorf(codes.AlreadyExists, "Directory %v already exists or is soft deleted.", in.GetDirectoryId())
	}

	// Generate VRF key.
	wrapped, err := privKeyOrGen(ctx, in.GetVrfPrivateKey(), s.keygen)
	if s := status.Convert(err); s.Code() != codes.OK {
		return nil, status.Errorf(s.Code(), "adminserver: keygen(): %v", s.Message())
	}
	vrfPriv, err := p256.NewFromWrappedKey(ctx, wrapped)
	if s := status.Convert(err); s.Code() != codes.OK {
		return nil, status.Errorf(s.Code(), "adminserver: NewFromWrappedKey(): %v", s.Message())
	}
	vrfPublicPB, err := der.ToPublicProto(vrfPriv.Public())
	if err != nil {
		return nil, err
	}

	// Create Trillian keys.
	logTreeArgs := treeConfig(logArgs, in.GetLogPrivateKey(), in.GetDirectoryId())
	logTree, err := client.CreateAndInitTree(ctx, logTreeArgs, s.logAdmin, s.tmap, s.tlog)
	if s := status.Convert(err); s.Code() != codes.OK {
		return nil, status.Errorf(s.Code(), "adminserver: CreateTree(log): %v", s.Message())
	}
	mapTreeArgs := treeConfig(mapArgs, in.GetMapPrivateKey(), in.GetDirectoryId())
	mapTree, err := client.CreateAndInitTree(ctx, mapTreeArgs, s.mapAdmin, s.tmap, s.tlog)
	if err != nil {
		// Delete log if map creation fails.
		if _, delErr := s.logAdmin.DeleteTree(ctx, &tpb.DeleteTreeRequest{TreeId: logTree.TreeId}); delErr != nil {
			return nil, status.Errorf(codes.Internal, "adminserver: CreateAndInitTree(map): %v, DeleteTree(%v): %v ", err, logTree.TreeId, delErr)
		}
		return nil, status.Errorf(codes.Internal, "adminserver: CreateAndInitTree(map): %v", err)
	}
	minInterval, err := ptypes.Duration(in.MinInterval)
	if s := status.Convert(err); s.Code() != codes.OK {
		return nil, status.Errorf(s.Code(), "adminserver: Duration(%v): %v", in.MinInterval, s.Message())
	}
	maxInterval, err := ptypes.Duration(in.MaxInterval)
	if s := status.Convert(err); s.Code() != codes.OK {
		return nil, status.Errorf(s.Code(), "adminserver: Duration(%v): %v", in.MaxInterval, s.Message())
	}

	// Initialize log with first map root.
	if err := s.initialize(ctx, logTree, mapTree); err != nil {
		// Delete log and map if initialization fails.
		_, delLogErr := s.logAdmin.DeleteTree(ctx, &tpb.DeleteTreeRequest{TreeId: logTree.TreeId})
		_, delMapErr := s.mapAdmin.DeleteTree(ctx, &tpb.DeleteTreeRequest{TreeId: mapTree.TreeId})
		return nil, status.Errorf(codes.Internal, "adminserver: init of log with first map root failed: %v. Cleanup: delete log %v: %v, delete map %v: %v",
			err, logTree.TreeId, delLogErr, mapTree.TreeId, delMapErr)
	}

	trimmedMap := trimTree(mapTree)
	trimmedLog := trimTree(logTree)

	// Create directory - {log, map} binding.
	dir := &directory.Directory{
		DirectoryID: in.GetDirectoryId(),
		Map:         trimmedMap,
		Log:         trimmedLog,
		VRF:         vrfPublicPB,
		VRFPriv:     wrapped,
		MinInterval: minInterval,
		MaxInterval: maxInterval,
	}
	if s := status.Convert(s.directories.Write(ctx, dir)); s.Code() != codes.OK {
		return nil, status.Errorf(s.Code(), "adminserver: directories.Write(): %v", s.Message())
	}

	// Create initial logs for writing.
	// TODO(#1063): Additional logs can be added at a later point to support increased server load.
	logIDs := []int64{1, 2}
	if s := status.Convert(s.logsAdmin.AddLogs(ctx, in.GetDirectoryId(), logIDs...)); s.Code() != codes.OK {
		return nil, status.Errorf(s.Code(), "adminserver: AddLogs(%+v): %v", logIDs, s.Message())
	}
	// Initialize the batches table.
	err = s.batcher.WriteBatchSources(ctx, in.GetDirectoryId(), 0, new(spb.MapMetadata))
	if s := status.Convert(err); s.Code() != codes.OK {
		return nil, status.Errorf(s.Code(), "adminserver: WriteBatchSources(): %v", s.Message())
	}

	d := &pb.Directory{
		DirectoryId: in.GetDirectoryId(),
		Log:         trimmedLog,
		Map:         trimmedMap,
		Vrf:         vrfPublicPB,
		MinInterval: in.MinInterval,
		MaxInterval: in.MaxInterval,
	}
	glog.Infof("Created directory: %+v", d)
	return d, nil
}

// initialize inserts the first (empty) SignedMapRoot into the log if it is empty.
// This keeps the log leaves in-sync with the map which starts off with an
// empty log root at map revision 0.
func (s *Server) initialize(ctx context.Context, logTree, mapTree *tpb.Tree) error {
	logID := logTree.GetTreeId()
	mapID := mapTree.GetTreeId()
	// TODO(gbelvin): Store and track trusted root.
	trustedRoot := types.LogRootV1{} // Automatically trust the first observed log root.

	logClient, err := client.NewFromTree(s.tlog, logTree, trustedRoot)
	if s := status.Convert(err); s.Code() != codes.OK {
		return status.Errorf(s.Code(), "adminserver: could not create log client: %v", s.Message())
	}

	// Wait for the latest log root to become available.
	logRoot, err := logClient.UpdateRoot(ctx)
	if s := status.Convert(err); s.Code() != codes.OK {
		return status.Errorf(s.Code(), "adminserver: UpdateRoot(): %v", s.Message())
	}

	req := &tpb.GetSignedMapRootByRevisionRequest{MapId: mapID, Revision: 0}
	// TODO(gbelvin): does this need to be in a retry loop?
	resp, err := s.tmap.GetSignedMapRootByRevision(ctx, req)
	if s := status.Convert(err); s.Code() != codes.OK {
		return status.Errorf(s.Code(), "adminserver: GetSignedMapRootByRevision(%v,0): %v", mapID, s.Message())
	}
	mapVerifier, err := client.NewMapVerifierFromTree(mapTree)
	if s := status.Convert(err); s.Code() != codes.OK {
		return status.Errorf(s.Code(), "adminserver: NewMapVerifierFromTree(): %v", s.Message())
	}
	mapRoot, err := mapVerifier.VerifySignedMapRoot(resp.GetMapRoot())
	if s := status.Convert(err); s.Code() != codes.OK {
		return status.Errorf(s.Code(), "adminserver: VerifySignedMapRoot(): %v", s.Message())
	}

	// If the tree is empty and the map is empty,
	// add the empty map root to the log.
	if logRoot.TreeSize != 0 || mapRoot.Revision != 0 {
		return nil // Init not needed.
	}

	glog.Infof("Initializing Trillian Log %v with empty map root", logID)

	if s := status.Convert(logClient.AddSequencedLeafAndWait(ctx, resp.GetMapRoot().GetMapRoot(), int64(mapRoot.Revision))); s.Code() != codes.OK {
		return status.Errorf(s.Code(), "adminserver: log.AddSequencedLeaf(%v): %v", mapRoot.Revision, s.Message())
	}
	return nil
}

// DeleteDirectory marks a directory as deleted, but does not immediately delete it.
func (s *Server) DeleteDirectory(ctx context.Context, in *pb.DeleteDirectoryRequest) (*empty.Empty, error) {
	d, err := s.GetDirectory(ctx, &pb.GetDirectoryRequest{DirectoryId: in.GetDirectoryId()})
	if err != nil {
		return nil, err
	}

	if err := s.directories.SetDelete(ctx, in.GetDirectoryId(), true); err != nil {
		return nil, err
	}

	_, delLogErr := s.logAdmin.DeleteTree(ctx, &tpb.DeleteTreeRequest{TreeId: d.Log.TreeId})
	_, delMapErr := s.mapAdmin.DeleteTree(ctx, &tpb.DeleteTreeRequest{TreeId: d.Map.TreeId})
	if delLogErr != nil || delMapErr != nil {
		return nil, status.Errorf(codes.Internal, "adminserver: delete log %v: %v, delete map %v: %v",
			d.Log.TreeId, delLogErr, d.Map.TreeId, delMapErr)
	}

	return &empty.Empty{}, nil
}

// UndeleteDirectory reactivates a deleted directory - provided that UndeleteDirectory is called sufficiently soon after
// DeleteDirectory.
func (s *Server) UndeleteDirectory(ctx context.Context, in *pb.UndeleteDirectoryRequest) (
	*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}

// ListInputLogs returns a list of input logs for a directory.
func (s *Server) ListInputLogs(ctx context.Context, in *pb.ListInputLogsRequest) (*pb.ListInputLogsResponse, error) {
	logIDs, err := s.logsAdmin.ListLogs(ctx, in.GetDirectoryId(), in.GetFilterWritable())
	if s := status.Convert(err); s.Code() != codes.OK {
		return nil, status.Errorf(s.Code(), "adminserver: ListLogs(): %v", s.Message())
	}
	inputLogs := make([]*pb.InputLog, 0, len(logIDs))
	for _, logID := range logIDs {
		inputLogs = append(inputLogs, &pb.InputLog{LogId: logID, Writable: true})
	}

	return &pb.ListInputLogsResponse{Logs: inputLogs}, nil
}

// CreateInputLog returns the created log.
func (s *Server) CreateInputLog(ctx context.Context, in *pb.InputLog) (*pb.InputLog, error) {
	err := s.logsAdmin.AddLogs(ctx, in.GetDirectoryId(), in.GetLogId())
	if s := status.Convert(err); s.Code() != codes.OK {
		return nil, status.Errorf(s.Code(), "adminserver: AddLogs(%+v): %v", in.GetLogId(), s.Message())
	}
	return &pb.InputLog{LogId: in.GetLogId(), Writable: true}, nil
}

// UpdateInputLog updates the write bit for an input log.
func (s *Server) UpdateInputLog(ctx context.Context, in *pb.InputLog) (*pb.InputLog, error) {
	err := s.logsAdmin.SetWritable(ctx, in.GetDirectoryId(), in.GetLogId(), in.GetWritable())
	if s := status.Convert(err); s.Code() != codes.OK {
		return nil, status.Errorf(s.Code(), "adminserver: SetWritable(): %v", s.Message())
	}
	return in, nil
}

// GarbageCollect looks for directories that have been deleted before the specified timestamp and fully deletes them.
func (s *Server) GarbageCollect(ctx context.Context, in *pb.GarbageCollectRequest) (*pb.GarbageCollectResponse, error) {
	before, err := ptypes.Timestamp(in.GetBefore())
	if err != nil {
		return nil, err
	}

	showDeleted := true
	directories, err := s.directories.List(ctx, showDeleted)
	if err != nil {
		return nil, err
	}

	// Search for directories deleted before in.Before.
	deleted := []*pb.Directory{}
	for _, d := range directories {
		if d.Deleted && d.DeletedTimestamp.Before(before) {
			req := &pb.GetDirectoryRequest{DirectoryId: d.DirectoryID, ShowDeleted: showDeleted}
			dproto, err := s.GetDirectory(ctx, req)
			if err != nil {
				return nil, err
			}
			if err := s.directories.Delete(ctx, d.DirectoryID); err != nil {
				return nil, err
			}
			deleted = append(deleted, dproto)
		}
	}

	return &pb.GarbageCollectResponse{Directories: deleted}, nil
}
