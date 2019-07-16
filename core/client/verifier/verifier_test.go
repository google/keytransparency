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

package verifier

import (
	"testing"

	"github.com/google/keytransparency/core/client/tracker"
	"github.com/google/keytransparency/core/testdata"
	"github.com/google/trillian/types"

	tpb "github.com/google/keytransparency/core/testdata/transcript_go_proto"
)

// Test vectors in core/testdata are generated by running
// go generate ./core/testdata
func TestTranscripts(t *testing.T) {
	for _, name := range []string{
		"TestEmptyGetAndUpdate",
	} {
		t.Run(name, func(t *testing.T) {
			transcript, err := testdata.ReadTranscript(name)
			if err != nil {
				t.Fatal(err)
			}
			RunTranscriptTest(t, transcript)
		})
	}
}

func RunTranscriptTest(t *testing.T, transcript *tpb.Transcript) {
	t.Helper()

	v, err := NewFromDirectory(transcript.Directory)
	if err != nil {
		t.Fatal(err)
	}

	for _, rpc := range transcript.Actions {
		t.Run(rpc.Desc, func(t *testing.T) {
			v.lt = tracker.NewFromSaved(v.lv, types.LogRootV1{
				TreeSize: uint64(rpc.LastVerifiedLogRoot.GetTreeSize()),
				RootHash: rpc.LastVerifiedLogRoot.GetRootHash(),
			})
			switch pair := rpc.ReqRespPair.(type) {
			case *tpb.Action_GetUser:
				v.LastVerifiedLogRoot()
				if err := v.VerifyGetUser(trusted, pair.GetUser.Request, pair.GetUser.Response); err != nil {
					t.Errorf("VerifyGetUser(): %v", err)
				}

			default:
				t.Fatalf("Unknown ReqRespPair: %T", pair)
			}
		})
	}
}
