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

// This package contains common type definitions and functions used by other
// packages. Types that can cause circular import should be added here.
package common

import (
	"crypto/sha256"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	proto "github.com/golang/protobuf/proto"
	ctmap "github.com/gdbelvin/e2e-key-server/proto/security_ctmap"
)

// Hash calculates the hash of the given data.
func Hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// EpochHead unmarshal and returns SignedEpochHead.EpochHead.
func EpochHead(signedHead *ctmap.SignedEpochHead) (*ctmap.EpochHead, error) {
	epochHead := new(ctmap.EpochHead)
	if err := proto.Unmarshal(signedHead.EpochHead, epochHead); err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "Cannot unmarshal epoch head")
	}
	return epochHead, nil
}
