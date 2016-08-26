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

package integration

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/google/key-transparency/cmd/client/grpcc"
	"github.com/google/key-transparency/core/authentication"

	"golang.org/x/net/context"

	ctmap "github.com/google/key-transparency/core/proto/ctmap"
	tpb "github.com/google/key-transparency/core/proto/kt_types_v1"
)

var (
	primaryKeys = map[string][]byte{
		"foo": []byte("bar"),
	}
)

func TestEmptyGetAndUpdate(t *testing.T) {
	auth := authentication.NewFake()
	env := NewEnv(t)
	defer env.Close(t)
	env.Client.RetryCount = 0

	for _, tc := range []struct {
		want   bool
		insert bool
		ctx    context.Context
		userID string
	}{
		{false, false, context.Background(), "noalice"}, // Empty
		{false, true, auth.NewContext("bob"), "bob"},    // Insert
		{false, false, context.Background(), "nocarol"}, // Empty
		{true, false, context.Background(), "bob"},      // Not Empty
		{true, true, auth.NewContext("bob"), "bob"},     // Update
	} {
		// Check profile.
		if err := env.checkProfile(tc.userID, tc.want); err != nil {
			t.Errorf("checkProfile(%v, %v) failed: %v", tc.userID, tc.want, err)
		}
		// Update profile.
		if tc.insert {
			req, err := env.Client.Update(tc.ctx, tc.userID, &tpb.Profile{Keys: primaryKeys})
			if got, want := err, grpcc.ErrRetry; got != want {
				t.Fatalf("Update(%v): %v, want %v", tc.userID, got, want)
			}
			if err := env.Signer.Sequence(); err != nil {
				t.Fatalf("Failed to sequence: %v", err)
			}
			if err := env.Signer.CreateEpoch(); err != nil {
				t.Fatalf("Failed to CreateEpoch: %v", err)
			}
			if err := env.Client.Retry(tc.ctx, req); err != nil {
				t.Errorf("Retry(%v): %v, want nil", req, err)
			}
		}
	}
}

// checkProfile ensures that the returned profile is as expected along with the
// keys it carries.
func (e *Env) checkProfile(userID string, want bool) error {
	profile, err := e.Client.GetEntry(context.Background(), userID)
	if err != nil {
		return fmt.Errorf("GetEntry(%v): %v, want nil", userID, err)
	}
	if got := profile != nil; got != want {
		return fmt.Errorf("GetEntry(%v): %v, want %v", userID, profile, want)
	}
	if want {
		if got, want := len(profile.GetKeys()), 1; got != want {
			return fmt.Errorf("len(GetKeys()) = %v, want; %v", got, want)
		}
		if got, want := profile.GetKeys(), primaryKeys; !reflect.DeepEqual(got, want) {
			return fmt.Errorf("GetKeys() = %v, want: %v", got, want)
		}
	}
	return nil
}

func TestUpdateValidation(t *testing.T) {
	env := NewEnv(t)
	defer env.Close(t)
	env.Client.RetryCount = 0

	auth := authentication.NewFake()
	profile := &tpb.Profile{
		Keys: map[string][]byte{
			"foo": []byte("bar"),
		},
	}

	for _, tc := range []struct {
		want    bool
		ctx     context.Context
		userID  string
		profile *tpb.Profile
	}{
		{false, context.Background(), "alice", profile},
		{false, auth.NewContext("carol"), "bob", profile},
		{true, auth.NewContext("dave"), "dave", profile},
		{true, auth.NewContext("eve"), "eve", profile},
	} {
		req, err := env.Client.Update(tc.ctx, tc.userID, tc.profile)

		// The first update response is always a retry.
		if got, want := err, grpcc.ErrRetry; (got == want) != tc.want {
			t.Fatalf("Update(%v): %v != %v, want %v", tc.userID, err, want, tc.want)
		}
		if tc.want {
			if err := env.Signer.Sequence(); err != nil {
				t.Fatalf("Failed to sequence: %v", err)
			}
			if err := env.Signer.CreateEpoch(); err != nil {
				t.Fatalf("Failed to CreateEpoch: %v", err)
			}
			if err := env.Client.Retry(tc.ctx, req); err != nil {
				t.Errorf("Retry(%v): %v, want nil", req, err)
			}
		}
	}
}

func TestListHistory(t *testing.T) {
	userID := "bob"
	ctx := authentication.NewFake().NewContext("bob")

	env := NewEnv(t)
	defer env.Close(t)
	env.Client.RetryCount = 0
	if err := env.setupHistory(ctx, userID); err != nil {
		t.Fatalf("setupHistory failed: %v", err)
	}

	for _, tc := range []struct {
		start, end  int64
		wantHistory []*tpb.Profile
		wantErr     bool
	}{
		{3, 3, []*tpb.Profile{cp(1)}, false},                                                   // single profile
		{3, 4, []*tpb.Profile{cp(1), cp(2)}, false},                                            // multiple profiles
		{1, 4, []*tpb.Profile{cp(1), cp(2)}, false},                                            // test 'nil' first profile(s)
		{3, 10, []*tpb.Profile{cp(1), cp(2), cp(3), cp(4), cp(5)}, false},                      // filtering
		{9, 16, []*tpb.Profile{cp(4), cp(5), cp(6)}, false},                                    // filtering consecutive resubmitted profiles
		{9, 20, []*tpb.Profile{cp(4), cp(5), cp(6), cp(5), cp(7)}, false},                      // no filtering of resubmitted profiles
		{1, 20, []*tpb.Profile{cp(1), cp(2), cp(3), cp(4), cp(5), cp(6), cp(5), cp(7)}, false}, // multiple pages
		{0, 20, []*tpb.Profile{}, true},                                                        // Invalid start epoch
		{1, 1000, []*tpb.Profile{}, true},                                                      // Invalid end epoch, beyond current epoch
	} {
		resp, err := env.Client.ListHistory(ctx, userID, tc.start, tc.end)
		if got, want := err != nil, tc.wantErr; got != want {
			t.Fatalf("ListHistory(_, %v, %v, %v) failed: %v, want err %v", userID, tc.start, tc.end, err, want)
		}
		// If there's a ListHistory error, skip the rest of the test.
		if err != nil {
			continue
		}

		// Sort received history by Epoch.
		gotHistory := sortHistory(resp)

		// Ensure that history has the correct number of profiles.
		if got, want := len(gotHistory), len(tc.wantHistory); got != want {
			t.Errorf("len(gotHistory)=%v, want %v", got, want)
			continue
		}
		// Ensure that history has the correct profiles in the correct
		// order.
		if !reflect.DeepEqual(gotHistory, tc.wantHistory) {
			t.Errorf("Invalid history: %v, want %v", gotHistory, tc.wantHistory)
		}
	}
}

func (e *Env) setupHistory(ctx context.Context, userID string) error {
	// Setup. Each profile entry is either nil, to indicate that the user
	// did not submit a new profile in that epoch, or contains the profile
	// that the user is submitting. The user profile history contains the
	// following profiles:
	// [nil, nil, 1, 2, 2, 2, 3, 3, 4, 5, 5, 5, 5, 5, 5, 6, 6, 5, 7, 7].
	// Note that profile 5 is submitted twice by the user to test that
	// filtering case.
	for _, p := range []*tpb.Profile{
		nil, nil, cp(1), cp(2), nil, nil, cp(3), nil,
		cp(4), cp(5), cp(5), nil, nil, nil, nil, cp(6),
		nil, cp(5), cp(7), nil,
	} {
		if p != nil {
			_, err := e.Client.Update(ctx, userID, p)
			// The first update response is always a retry.
			if got, want := err, grpcc.ErrRetry; got != want {
				return fmt.Errorf("Update(%v)=(_, %v), want (_, %v)", userID, got, want)
			}
			if err := e.Signer.Sequence(); err != nil {
				return fmt.Errorf("Failed to sequence: %v", err)
			}
		}
		if err := e.Signer.CreateEpoch(); err != nil {
			return fmt.Errorf("Failed to CreateEpoch: %v", err)
		}
	}
	return nil
}

func sortHistory(history map[*ctmap.MapHead]*tpb.Profile) []*tpb.Profile {
	// keys is created with 0 length and the appropriate capacity to avoid
	// underlying reallocation in append.
	keys := make([]*ctmap.MapHead, 0, len(history))
	for k := range history {
		keys = append(keys, k)
	}
	sort.Sort(mapHeads(keys))
	profiles := make([]*tpb.Profile, len(keys))
	for i, k := range keys {
		profiles[i] = history[k]
	}
	return profiles
}

// MapHead sorter.
type mapHeads []*ctmap.MapHead

func (m mapHeads) Len() int           { return len(m) }
func (m mapHeads) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }
func (m mapHeads) Less(i, j int) bool { return m[i].Epoch < m[j].Epoch }

// cp creates a dummy profile using the passed tag.
func cp(tag int) *tpb.Profile {
	return &tpb.Profile{
		Keys: map[string][]byte{
			fmt.Sprintf("foo%v", tag): []byte(fmt.Sprintf("bar%v", tag)),
		},
	}
}

// TODO: Test AppID filtering when implemented.
