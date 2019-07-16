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

// Package tracker verifies consistency proofs
package tracker

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/google/trillian/types"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tclient "github.com/google/trillian/client"
)

// UpdateTrustedPredicate return a bool indicating whether the local reference
// for the latest SignedLogRoot should be updated.
type UpdateTrustedPredicate func(cntRoot, newRoot types.LogRootV1) bool

// LogTracker keeps a continuous series of consistent log roots.
type LogTracker struct {
	trusted       types.LogRootV1
	v             *tclient.LogVerifier
	updateTrusted UpdateTrustedPredicate
}

// New creates a log tracker from no trusted root.
func New(lv *tclient.LogVerifier) *LogTracker {
	return NewFromSaved(lv, types.LogRootV1{})
}

// NewFromSaved creates a log tracker from a previously saved trusted root.
func NewFromSaved(lv *tclient.LogVerifier, lr types.LogRootV1) *LogTracker {
	return &LogTracker{v: lv, trusted: lr, updateTrusted: isNewer}
}

// LastVerifiedLogRoot retrieves the tree size of the latest log root
// and it blocks further requests until VerifyRoot is called.
func (l *LogTracker) LastVerifiedLogRoot() *pb.LogRootRequest {
	return l.logRootRequest()
}

func (l *LogTracker) logRootRequest() *pb.LogRootRequest {
	return &pb.LogRootRequest{
		TreeSize: int64(l.trusted.TreeSize),
		RootHash: l.trusted.RootHash,
	}
}

// VerifyLogRoot verifies root and updates the trusted root if it is newer.
// VerifyLogRoot unblocks the next call to LastVerifiedTreeSize.
// req must come from LastVerifiedLogRoot()
func (l *LogTracker) VerifyLogRoot(req *pb.LogRootRequest, root *pb.LogRoot) (*types.LogRootV1, error) {
	if want := l.logRootRequest(); !proto.Equal(req, want) {
		glog.Warningf("logtracker: unexpected logRootRequest: %v, want %v", req, want)
		return nil, fmt.Errorf("unexpected request %v, want %v", req, want)
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

// SetUpdatePredicate allows tests to have finer grained control over when
// the trusted root is updated.
func (l *LogTracker) SetUpdatePredicate(f UpdateTrustedPredicate) {
	l.updateTrusted = f
}

// isNewer returns true when newRoot is newer than cntRoot.
func isNewer(cntRoot, newRoot types.LogRootV1) bool {
	if newRoot.TimestampNanos <= cntRoot.TimestampNanos ||
		newRoot.TreeSize < cntRoot.TreeSize {
		// The new root is older than the one we currently have.
		return false
	}
	return true
}
