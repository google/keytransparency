// Copyright 2016 Google Inc. All Rights Reserved.
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

package fake

import (
	"context"

	"google.golang.org/grpc"

	tpb "github.com/google/trillian"
)

// LogServer only stores tree size.
type LogServer struct {
	treeSize int64
}

// NewTrillianLogClient returns a fake trillian log client.
func NewTrillianLogClient() *LogServer {
	return &LogServer{}
}

// QueueLeaf increments the size of the tree.
func (l *LogServer) QueueLeaf(context.Context, *tpb.QueueLeafRequest, ...grpc.CallOption) (*tpb.QueueLeafResponse, error) {
	l.treeSize++
	return nil, nil
}

// QueueLeaves is not implemented.
func (*LogServer) QueueLeaves(context.Context, *tpb.QueueLeavesRequest, ...grpc.CallOption) (*tpb.QueueLeavesResponse, error) {
	panic("not implemented")
}

// GetInclusionProof returns an empty proof.
func (*LogServer) GetInclusionProof(context.Context, *tpb.GetInclusionProofRequest, ...grpc.CallOption) (*tpb.GetInclusionProofResponse, error) {
	return &tpb.GetInclusionProofResponse{}, nil
}

// GetInclusionProofByHash is not implemented.
func (*LogServer) GetInclusionProofByHash(context.Context, *tpb.GetInclusionProofByHashRequest, ...grpc.CallOption) (*tpb.GetInclusionProofByHashResponse, error) {
	panic("not implemented")
}

// GetConsistencyProof returns an empty proof.
func (*LogServer) GetConsistencyProof(context.Context, *tpb.GetConsistencyProofRequest, ...grpc.CallOption) (*tpb.GetConsistencyProofResponse, error) {
	return &tpb.GetConsistencyProofResponse{}, nil
}

// GetLatestSignedLogRoot returns the current tree size.
func (l *LogServer) GetLatestSignedLogRoot(context.Context, *tpb.GetLatestSignedLogRootRequest, ...grpc.CallOption) (*tpb.GetLatestSignedLogRootResponse, error) {
	return &tpb.GetLatestSignedLogRootResponse{
		SignedLogRoot: &tpb.SignedLogRoot{
			TreeSize: l.treeSize,
		},
	}, nil
}

// GetSequencedLeafCount is not implemented.
func (*LogServer) GetSequencedLeafCount(context.Context, *tpb.GetSequencedLeafCountRequest, ...grpc.CallOption) (*tpb.GetSequencedLeafCountResponse, error) {
	panic("not implemented")
}

// GetLeavesByIndex is not implemented.
func (*LogServer) GetLeavesByIndex(context.Context, *tpb.GetLeavesByIndexRequest, ...grpc.CallOption) (*tpb.GetLeavesByIndexResponse, error) {
	panic("not implemented")
}

// GetLeavesByHash is not implemented.
func (*LogServer) GetLeavesByHash(context.Context, *tpb.GetLeavesByHashRequest, ...grpc.CallOption) (*tpb.GetLeavesByHashResponse, error) {
	panic("not implemented")
}

// GetEntryAndProof is not implemented.
func (*LogServer) GetEntryAndProof(context.Context, *tpb.GetEntryAndProofRequest, ...grpc.CallOption) (*tpb.GetEntryAndProofResponse, error) {
	panic("not implemented")
}

// GetLeavesByRange is not implemented.
func (*LogServer) GetLeavesByRange(context.Context, *tpb.GetLeavesByRangeRequest, ...grpc.CallOption) (*tpb.GetLeavesByRangeResponse, error) {
	panic("not implemented")
}
