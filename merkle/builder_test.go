// Copyright 2015 Google Inc. All Rights Reserved.
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

package merkle

import (
	"encoding/hex"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	internalpb "github.com/google/e2e-key-server/proto/internal"
)

// For reference:
// Index: 5333d14e221b9995cc8c61b5d4af14a1c689489605fed96fff3250e45c5b1b0d
// Valid entry: 22205333d14e221b9995cc8c61b5d4af14a1c689489605fed96fff3250e45c5b1b0d

const (
	testEpoch        = 1
	validEntryUpdate = "1a2222205333d14e221b9995cc8c61b5d4af14a1c689489605fed96fff3250e45c5b1b0d"
	// Contains a signed entry update with invalid entry.
	invalidEntry = "1a21205333d14e221b9995cc8c61b5d4af14a1c689489605fed96fff3250e45c5b1b0d"
	// Contains a signed entry update with a short index.
	invalidIndex = "1a06220412345678"
)

func TestPost(t *testing.T) {
	m := New()
	tests := []struct {
		entryUpdate string
		code        codes.Code
	}{
		{validEntryUpdate, codes.OK},
		// Taking the first 10 (or any number of) bytes of the valid
		// entry update simulate a broken entry update that cannot be
		// unmarshaled.
		{validEntryUpdate[:10], codes.Internal},
		{invalidEntry, codes.Internal},
		{invalidIndex, codes.InvalidArgument},
	}

	for i, test := range tests {
		euBytes, _ := hex.DecodeString(test.entryUpdate)
		es := &internalpb.EntryStorage{
			Epoch:       testEpoch,
			EntryUpdate: euBytes,
		}
		err := post(m, es)
		if got, want := grpc.Code(err), test.code; got != want {
			t.Errorf("Test[%v]: post()=%v, want %v, %v", i, got, want, err)
		}
	}
}
