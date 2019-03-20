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

package codes

import "google.golang.org/grpc/codes"

// Code is an enum that represents a kind of error.
type Code int

const (
	Unknown Code = iota
	OK
	Marshal
	Unmarshal
	TooManyMapLeaves
	NoMsgs
	NoValidMutations
	NilKeyset
	NewVerifier
	PermissionDenied
	PreviousHash
	TooLarge
	Replay
)

func (c Code) GRPCCode() codes.Code {
	switch c {
	case OK:
		return codes.OK
	case PermissionDenied:
		return codes.PermissionDenied
	default:
		return codes.Unknown
	}
}
