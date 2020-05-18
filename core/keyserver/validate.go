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

package keyserver

// validate performs correctness checking on each v2 message type.

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto" //nolint:staticcheck

	"github.com/google/keytransparency/core/crypto/commitments"
	"github.com/google/keytransparency/core/crypto/vrf"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// Maximum period of time to allow between CreationTime and server time.
const (
	MaxClockDrift = 5 * time.Minute
	MinNonceLen   = 16
)

var (
	// ErrNoCommitted occurs when the committed field is missing.
	ErrNoCommitted = errors.New("missing commitment")
	// ErrCommittedKeyLen occurs when the committed key is too small.
	ErrCommittedKeyLen = errors.New("committed.key is too small")
	// ErrWrongIndex occurs when the index in key value does not match the
	// output of VRF.
	ErrWrongIndex = errors.New("index does not match VRF")
	// ErrInvalidStart occurs when the start revision of ListEntryHistoryRequest
	// is not valid (not in [1, currentRevision]).
	ErrInvalidStart = errors.New("invalid start revision")
	// ErrInvalidPageSize occurs when the page size is < 0.
	ErrInvalidPageSize = errors.New("invalid page size")
	// ErrInvalidEnd occurs when the end revision of the ListUserRevisionsRequest
	// is not in [start, currentRevision].
	ErrInvalidEnd = errors.New("invalid end revision")
)

// validateEntryUpdate verifies
// - Commitment in SignedEntryUpdate matches the serialized profile.
func validateEntryUpdate(in *pb.EntryUpdate, vrfPriv vrf.PrivateKey) error {
	var entry pb.Entry
	if err := proto.Unmarshal(in.GetMutation().GetEntry(), &entry); err != nil {
		return err
	}

	// Verify Index / VRF
	index, _ := vrfPriv.Evaluate([]byte(in.UserId))
	if got, want := entry.Index, index[:]; !bytes.Equal(got, want) {
		return ErrWrongIndex
	}

	// Verify correct commitment to profile.
	committed := in.GetCommitted()
	if committed == nil {
		return ErrNoCommitted
	}
	if got, want := len(committed.Key), MinNonceLen; got < want {
		return ErrCommittedKeyLen
	}
	return commitments.Verify(in.UserId, entry.Commitment, committed.Data, committed.Key)
}

// validateListEntryHistoryRequest ensures that start revision is in range [1,
// currentRevision] and sets the page size if it is 0 or larger than what the server
// can return (due to reaching currentRevision).
func validateListEntryHistoryRequest(in *pb.ListEntryHistoryRequest, currentRevision int64) error {
	if in.Start < 0 || in.Start > currentRevision {
		return ErrInvalidStart
	}

	switch {
	case in.PageSize < 0:
		return fmt.Errorf("invalid page size")
	case in.PageSize == 0:
		in.PageSize = defaultPageSize
	case in.PageSize > maxPageSize:
		in.PageSize = maxPageSize
	}
	// Ensure in.PageSize does not exceed currentRevision.
	if in.Start+int64(in.PageSize) > currentRevision {
		in.PageSize = int32(currentRevision - in.Start + 1)
	}
	return nil
}

// validateListUserRevisionsRequest checks the bounds on start and end revisions and returns an appropriate number of
// revisions to return for this request.
func validateListUserRevisionsRequest(in *pb.ListUserRevisionsRequest, pageStart, newestRevision int64) (int64, error) {
	if in.StartRevision < 0 || in.StartRevision > newestRevision {
		return 0, ErrInvalidStart
	}
	if in.EndRevision < in.StartRevision || in.EndRevision > newestRevision {
		return 0, ErrInvalidEnd
	}

	revisions := int64(in.PageSize)
	switch {
	case in.PageSize < 0:
		return 0, fmt.Errorf("invalid page size")
	case in.PageSize == 0:
		revisions = int64(defaultPageSize)
	case in.PageSize > maxPageSize:
		revisions = int64(maxPageSize)
	}
	if pageStart+revisions > in.EndRevision {
		revisions = in.EndRevision - pageStart + 1
	}
	return revisions, nil
}

// validateBatchListUserRevisionsRequest checks the bounds on start and end revisions and returns an appropriate number of
// revisions to return for this request.
func validateBatchListUserRevisionsRequest(in *pb.BatchListUserRevisionsRequest, pageStart, newestRevision int64) (int64, error) {
	if in.StartRevision < 0 || in.StartRevision > newestRevision {
		return 0, ErrInvalidStart
	}
	if in.EndRevision < in.StartRevision || in.EndRevision > newestRevision {
		return 0, ErrInvalidEnd
	}

	revisions := int64(in.PageSize)
	switch {
	case in.PageSize < 0:
		return 0, fmt.Errorf("invalid page size")
	case in.PageSize == 0:
		revisions = int64(defaultPageSize)
	case in.PageSize > maxPageSize:
		revisions = int64(maxPageSize)
	}
	if pageStart+revisions > in.EndRevision {
		revisions = in.EndRevision - pageStart + 1
	}
	return revisions, nil
}

// validateGetRevisionRequest ensures that start revision starts with 1
func validateGetRevisionRequest(in *pb.GetRevisionRequest) error {
	if in.Revision < 0 {
		return ErrInvalidStart
	}
	return nil
}

func validateListMutationsRequest(in *pb.ListMutationsRequest) error {
	if in.Revision < 1 {
		return ErrInvalidStart
	}
	switch {
	case in.PageSize < 0:
		return ErrInvalidPageSize
	case in.PageSize == 0:
		in.PageSize = defaultPageSize
	case in.PageSize > maxPageSize:
		in.PageSize = maxPageSize
	}
	return nil
}
