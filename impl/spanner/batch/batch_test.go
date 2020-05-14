// Copyright 2020 Google Inc. All Rights Reserved.
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

package batch

import (
	"context"
	"testing"

	"github.com/google/keytransparency/core/integration/storagetest"
	"github.com/google/keytransparency/core/sequencer"
	"github.com/google/keytransparency/impl/spanner/directory"
	"github.com/google/keytransparency/impl/spanner/testutil"
	"github.com/google/trillian/crypto/keyspb"

	dtype "github.com/google/keytransparency/core/directory"
	ktspanner "github.com/google/keytransparency/impl/spanner"
	tpb "github.com/google/trillian"
)

func NewForTest(ctx context.Context, t *testing.T, dirID string) sequencer.Batcher {
	t.Helper()
	ddl, err := ktspanner.ReadDDL()
	if err != nil {
		t.Fatal(err)
	}
	client := testutil.CreateDatabase(ctx, t, ddl)
	b := New(client)

	if err := directory.New(client).Write(ctx, &dtype.Directory{
		DirectoryID: dirID,
		Map:         &tpb.Tree{},
		Log:         &tpb.Tree{},
		VRFPriv:     &keyspb.PrivateKey{Der: []byte("privkeybytes")},
	}); err != nil {
		t.Fatalf("directories.Write(%v): %v", dirID, err)
	}

	return b
}

func TestNewForTest(t *testing.T) {
	ctx := context.Background()
	directoryID := "new"
	NewForTest(ctx, t, directoryID)
}

func TestBatchIntegration(t *testing.T) {
	storagetest.RunBatchStorageTests(t, NewForTest)
}
