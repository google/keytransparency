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

package mutation

import (
	"errors"
	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
)

const (
	// Each page contains pageSize profiles. Each profile contains multiple
	// keys. Assuming 2 keys per profile (each of size 2048-bit), a page of
	// size 16 will contain about 8KB of data.
	defaultPageSize = 16
	// Maximum allowed requested page size to prevent DOS.
	maxPageSize = 16
)

var (
	// ErrInvalidStart occurs when the start epoch of ListEntryHistoryRequest
	// is not valid (not in [1, currentEpoch]).
	ErrInvalidStart = errors.New("invalid start epoch")
	// ErrInvalidPagesize occurs when the page size is > 0.
	ErrInvalidPagesize = errors.New("Invalid page size")
)

// validateGetMutationsRequest ensures that start epoch starts with 1 and that
// page size is > 0.
func validateGetMutationsRequest(in *tpb.GetMutationsRequest) error {
	if in.Epoch <= 0 {
		return ErrInvalidStart
	}
	switch {
	case in.PageSize < 0:
		return ErrInvalidPagesize
	case in.PageSize == 0:
		in.PageSize = defaultPageSize
	case in.PageSize > maxPageSize:
		in.PageSize = maxPageSize
	}
	return nil
}
