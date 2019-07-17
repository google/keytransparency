// Copyright 2019 Google Inc. All Rights Reserved.
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

package tracker

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tpb "github.com/google/trillian"
)

func TestVerifyLogRoot(t *testing.T) {
	type rpc struct {
		req      *pb.LogRootRequest
		resp     *pb.LogRoot
		want     types.LogRootV1
		wantCode codes.Code
	}

	for _, tc := range []struct {
		desc  string
		saved types.LogRootV1
		rpcs  []rpc
	}{
		{desc: "nil req", rpcs: []rpc{{wantCode: codes.InvalidArgument}}},
		{desc: "empty root", rpcs: []rpc{{req: &pb.LogRootRequest{}, resp: mustSignLogRoot(t, types.LogRootV1{})}}},
		{desc: "1 rpc", rpcs: []rpc{{req: &pb.LogRootRequest{}, resp: mustSignLogRoot(t, types.LogRootV1{TreeSize: 1})}}},
		{desc: "2 rpc invalid", rpcs: []rpc{
			{req: &pb.LogRootRequest{}, resp: mustSignLogRoot(t, types.LogRootV1{TreeSize: 1})},
			{req: &pb.LogRootRequest{}, resp: mustSignLogRoot(t, types.LogRootV1{TreeSize: 2}), wantCode: codes.InvalidArgument},
		}},
		{desc: "2 rpc", rpcs: []rpc{
			{req: &pb.LogRootRequest{}, resp: mustSignLogRoot(t, types.LogRootV1{TreeSize: 1})},
			{req: &pb.LogRootRequest{TreeSize: 1}, resp: mustSignLogRoot(t, types.LogRootV1{TreeSize: 2})},
		}},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			lt := NewFromSaved(&fakeLogVerifier{}, tc.saved)
			for _, r := range tc.rpcs {
				got, err := lt.VerifyLogRoot(r.req, r.resp)
				if got := status.Code(err); got != r.wantCode {
					t.Errorf("VerifyLogRoot(): %v (%v), want %v", err, got, r.wantCode)
				}
				if err != nil {
					continue
				}
				if cmp.Equal(*got, r.want) {
					t.Errorf("VerifyLogRoot(): %v, want %v", got, r.want)
				}
			}
		})
	}
}

func mustSignLogRoot(t *testing.T, lr types.LogRootV1) *pb.LogRoot {
	t.Helper()
	logRoot, err := lr.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return &pb.LogRoot{
		LogRoot: &tpb.SignedLogRoot{
			LogRoot: logRoot,
		},
	}
}

type fakeLogVerifier struct{}

func (*fakeLogVerifier) VerifyRoot(trusted *types.LogRootV1, r *tpb.SignedLogRoot, consistency [][]byte) (*types.LogRootV1, error) {
	var logRoot types.LogRootV1
	if err := logRoot.UnmarshalBinary(r.GetLogRoot()); err != nil {
		return nil, err
	}
	return &logRoot, nil
}
