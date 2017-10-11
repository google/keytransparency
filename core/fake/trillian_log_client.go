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

	"github.com/google/trillian"
	"google.golang.org/grpc"
)

type logServer struct {
	treeSize int64
}

// NewFakeTrillianLogClient returns a fake trillian log client.
func NewFakeTrillianLogClient() trillian.TrillianLogClient {
	return &logServer{}
}

func (l *logServer) QueueLeaf(ctx context.Context, in *trillian.QueueLeafRequest, opts ...grpc.CallOption) (*trillian.QueueLeafResponse, error) {
	l.treeSize++
	return nil, nil
}

func (l *logServer) QueueLeaves(ctx context.Context, in *trillian.QueueLeavesRequest, opts ...grpc.CallOption) (*trillian.QueueLeavesResponse, error) {
	panic("not implemented")
}

func (l *logServer) GetInclusionProof(ctx context.Context, in *trillian.GetInclusionProofRequest, opts ...grpc.CallOption) (*trillian.GetInclusionProofResponse, error) {
	return &trillian.GetInclusionProofResponse{}, nil
}

func (l *logServer) GetInclusionProofByHash(ctx context.Context, in *trillian.GetInclusionProofByHashRequest, opts ...grpc.CallOption) (*trillian.GetInclusionProofByHashResponse, error) {
	panic("not implemented")
}

func (l *logServer) GetConsistencyProof(ctx context.Context, in *trillian.GetConsistencyProofRequest, opts ...grpc.CallOption) (*trillian.GetConsistencyProofResponse, error) {
	return &trillian.GetConsistencyProofResponse{}, nil
}

func (l *logServer) GetLatestSignedLogRoot(ctx context.Context, in *trillian.GetLatestSignedLogRootRequest, opts ...grpc.CallOption) (*trillian.GetLatestSignedLogRootResponse, error) {
	return &trillian.GetLatestSignedLogRootResponse{
		SignedLogRoot: &trillian.SignedLogRoot{
			TreeSize: l.treeSize,
		},
	}, nil
}

func (l *logServer) GetSequencedLeafCount(ctx context.Context, in *trillian.GetSequencedLeafCountRequest, opts ...grpc.CallOption) (*trillian.GetSequencedLeafCountResponse, error) {
	panic("not implemented")
}

func (l *logServer) GetLeavesByIndex(ctx context.Context, in *trillian.GetLeavesByIndexRequest, opts ...grpc.CallOption) (*trillian.GetLeavesByIndexResponse, error) {
	panic("not implemented")
}

func (l *logServer) GetLeavesByHash(ctx context.Context, in *trillian.GetLeavesByHashRequest, opts ...grpc.CallOption) (*trillian.GetLeavesByHashResponse, error) {
	panic("not implemented")
}

func (l *logServer) GetEntryAndProof(ctx context.Context, in *trillian.GetEntryAndProofRequest, opts ...grpc.CallOption) (*trillian.GetEntryAndProofResponse, error) {
	panic("not implemented")
}
