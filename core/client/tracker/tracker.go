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
	"sync"

	"github.com/golang/glog"
	"github.com/google/trillian/types"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tclient "github.com/google/trillian/client"
)

// LogTracker keeps a continuous series of consistent log roots.
type LogTracker struct {
	trusted types.LogRootV1
	mu      sync.Mutex
	v       *tclient.LogVerifier
}

func New(lv *tclient.LogVerifier) *LogTracker {
	return &LogTracker{v: lv}
}

// LastVerifiedTreeSize retrieves the tree size of the latest log root
// and it blocks further requests until VerifyRoot is called.
func (l *LogTracker) LastVerifiedTreeSize() int64 {
	l.mu.Lock()
	return int64(l.trusted.TreeSize)
}

// VerifyRoot verifies root and updates the trusted root if it is newer.
// VerifyRoot unblocks the next call to LastVerifiedTreeSize.
// It is a run-time error if LastVerifiedTreeSize has not previously been called.
func (l *LogTracker) VerifyRoot(root *pb.LogRoot) (*types.LogRootV1, error) {
	defer l.mu.Unlock()
	logRoot, err := l.v.VerifyRoot(&l.trusted,
		root.GetLogRoot(),
		root.GetLogConsistency())
	if err != nil {
		return nil, err
	}
	l.updateTrusted(logRoot)
	return logRoot, nil
}

// updateTrusted sets the local reference for the latest SignedLogRoot
// if newTrusted is newer than the current stored root.
func (l *LogTracker) updateTrusted(newRoot *types.LogRootV1) bool {
	if newRoot.TimestampNanos <= l.trusted.TimestampNanos ||
		newRoot.TreeSize < l.trusted.TreeSize {
		// The new root is older than the one we currently have.
		return false
	}
	l.trusted = *newRoot
	glog.Infof("Trusted root updated to TreeSize %v", l.trusted.TreeSize)
	return true
}
