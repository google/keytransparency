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

// Package tracker tracks log roots and verifies consistency proofs between them.
package tracker

import (
	"sync"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tpb "github.com/google/trillian"
)

// UpdateTrustedPredicate returns a bool indicating whether the local reference
// for the latest SignedLogRoot should be updated.
type UpdateTrustedPredicate func(cntRoot, newRoot types.LogRootV1) bool

// LogRootVerifier verifies a Trillian Log Root.
type LogRootVerifier interface {
	// VerifyRoot checks the signature of newRoot and the consistency proof if trusted.TreeSize != 0.
	VerifyRoot(trusted *types.LogRootV1, newRoot *tpb.SignedLogRoot, proof [][]byte) (*types.LogRootV1, error)
}

// LogTracker tracks a series of consistent log roots.
type LogTracker struct {
	trusted       types.LogRootV1
	v             LogRootVerifier
	updateTrusted UpdateTrustedPredicate
	mu            sync.RWMutex
}

// NewSynchronous creates a log tracker from no trusted root.
func NewSynchronous(lv LogRootVerifier) *LogTracker {
	return NewFromSaved(lv, types.LogRootV1{})
}

// NewFromSaved creates a log tracker from a previously saved trusted root.
func NewFromSaved(lv LogRootVerifier, lr types.LogRootV1) *LogTracker {
	return &LogTracker{v: lv, trusted: lr, updateTrusted: isNewer}
}

// LastVerifiedLogRoot retrieves the tree size of the latest log root.
func (l *LogTracker) LastVerifiedLogRoot() *pb.LogRootRequest {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.logRootRequest()
}

func (l *LogTracker) logRootRequest() *pb.LogRootRequest {
	return &pb.LogRootRequest{
		TreeSize: int64(l.trusted.TreeSize),
		RootHash: l.trusted.RootHash,
	}
}

// VerifyLogRoot verifies root and updates the trusted root if it is newer.
// state must be equal to the most recent value from LastVerifiedLogRoot().
// If two clients race to VerifyLogRoot at the same time, if one of them updates the root, the other will fail.
func (l *LogTracker) VerifyLogRoot(state *pb.LogRootRequest, root *pb.LogRoot) (*types.LogRootV1, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if want := l.logRootRequest(); !proto.Equal(state, want) {
		glog.Warningf("logtracker: unexpected logRootRequest: %v, want %v", state, want)
		return nil, status.Errorf(codes.InvalidArgument, "out of order VerifyLogRoot(%v, _), want %v", state, want)
	}

	logRoot, err := l.v.VerifyRoot(&l.trusted,
		root.GetLogRoot(),
		root.GetLogConsistency())
	if err != nil {
		return nil, err
	}
	if l.updateTrusted(l.trusted, *logRoot) {
		l.trusted = *logRoot
		glog.Infof("Trusted root updated to TreeSize %v", l.trusted.TreeSize)
	}
	return logRoot, nil
}

// SetUpdatePredicate allows relying parties to have finer grained control over when the trusted root is updated.
// It is legal to set the predicate at any time, but it makes the most sense to do so before any other calls.
func (l *LogTracker) SetUpdatePredicate(f UpdateTrustedPredicate) {
	l.updateTrusted = f
}

// isNewer returns true when newRoot is newer than cntRoot.
func isNewer(cntRoot, newRoot types.LogRootV1) bool {
	if newRoot.TreeSize > cntRoot.TreeSize {
		return true
	}
	if newRoot.TreeSize == cntRoot.TreeSize &&
		newRoot.TimestampNanos > cntRoot.TimestampNanos {
		return true
	}
	// The new root is older or smaller than the one we currently have.
	return false
}
