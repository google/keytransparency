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

package monitor

import (
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

func TestGetMutations(t *testing.T) {
	srv := New()
	_, err := srv.GetMutations(nil, nil)
	if got, want := grpc.Code(err), codes.Unimplemented; got != want {
		t.Errorf("GetMutations(_, _): %v, want %v", got, want)
	}
}

func TestGetMutationsStream(t *testing.T) {
	srv := New()
	err := srv.GetMutationsStream(nil, nil)
	if got, want := grpc.Code(err), codes.Unimplemented; got != want {
		t.Errorf("GetMutationsStream(_, _): %v, want %v", got, want)
	}
}
