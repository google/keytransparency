// Copyright 2018 Google Inc. All Rights Reserved.
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

// Package testdata contains data and data types for interoperability testing.
package testdata

import (
	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// GetUserResponseVector is a captured GetUserResponse that should verify without errors.
type GetUserResponseVector struct {
	Desc        string
	UserID      string
	Resp        *pb.GetUserResponse
	TrustNewLog bool
}

// BatchListUserRevisionsResponseVector is a captured BatchListUserRevisionsResponse that should verify without errors.
type BatchListUserRevisionsResponseVector struct {
	Desc    string
	UserIDs []string
	Resp    *pb.BatchListUserRevisionsResponse
}

// ResponseVector is a captured response that should verify without errors.
type ResponseVector struct {
        Desc    string
        UserIDs []string
	GetUserResp    *pb.GetUserResponse
        BatchListUserRevisionsResp    *pb.BatchListUserRevisionsResponse
	TrustNewLog bool
}
