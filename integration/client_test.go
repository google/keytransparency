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
	"testing"

	"github.com/google/key-transparency/core/authentication"
	"github.com/google/key-transparency/core/client"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	tpb "github.com/google/key-transparency/core/proto/kt_types_v1"
)

var (
	primaryKeys = map[string][]byte{
		"foo": []byte("bar"),
	}
)

type UserInfo struct {
	userID string
	ctx    context.Context
}

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
			if got, want := err, client.ErrRetry; got != want {
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
		if got, want := err, client.ErrRetry; (got == want) != tc.want {
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
	auth := authentication.NewFake()
	userInfo := []UserInfo{
		{"alice", auth.NewContext("alice")},
		{"bob", auth.NewContext("bob")},
		{"dave", auth.NewContext("dave")},
	}

	for _, tc := range []struct {
		// The length of users and profiles *must* match.
		users    []int
		profiles []int
		listUser int
		end      int64
		// History profiles are in reversed order.
		wantHistory []int
		err         codes.Code
	}{
		{
			[]int{0},
			[]int{0},
			0,
			1,
			[]int{0},
			codes.OK,
		}, // Single user, single profile
		{
			[]int{0, 0},
			[]int{0, 1},
			0,
			1,
			[]int{0, 1},
			codes.OK,
		}, // Single user, multiple profiles, no filtering
		{
			[]int{0, 0, 1, 0, 1, 0, 0, 1, 1},
			[]int{1, 2, 3, 4, 5, 6, 7, 8, 9},
			0,
			9,
			[]int{1, 2, 4, 6, 7},
			codes.OK,
		}, // Two users, multiple profiles
		{
			[]int{0, 0, 1, 0, 1},
			[]int{1, 2, 3, 4, 5},
			1,
			5,
			[]int{3, 5},
			codes.OK,
		}, // Two users, multiple profiles, test 'nil' first profile(s)
		{
			[]int{1, 2, 0, 0, 1, 1, 2, 0, 0, 0, 1, 1, 2, 0, 1},
			[]int{1, 2, 3, 2, 4, 6, 4, 5, 4, 3, 3, 7, 5, 1, 4},
			2,
			15,
			[]int{2, 4, 5},
			codes.OK,
		}, // Three users, multiple profiles (filtering should work)
		{
			[]int{1, 2, 0, 0, 1, 1, 2, 0, 2, 0, 0, 1, 1, 2, 0, 1},
			[]int{1, 2, 3, 2, 4, 6, 4, 5, 4, 4, 3, 3, 7, 5, 1, 4},
			2,
			16,
			[]int{2, 4, 5},
			codes.OK,
		}, // Three users, multiple (consecutive resubmission) profiles
		{
			[]int{1, 2, 0, 0, 2, 0, 1, 2, 2, 1, 1, 1, 0, 0, 2, 1},
			[]int{9, 3, 5, 3, 6, 1, 3, 5, 6, 7, 2, 6, 9, 8, 5, 9},
			1,
			16,
			[]int{9, 3, 7, 2, 6, 9},
			codes.OK,
		}, // Three users, multiple (resubmitted) profiles
		{
			[]int{0, 1, 2, 0, 2, 2, 1, 0, 0, 2, 1, 0, 2, 1, 2, 0, 0, 2, 1, 2, 0},
			[]int{4, 5, 8, 3, 2, 8, 9, 1, 0, 3, 4, 7, 6, 3, 1, 7, 0, 3, 6, 7, 2},
			1,
			21,
			[]int{5, 9, 4, 3, 6},
			codes.OK,
		}, // Multiple pages
		{
			[]int{0, 1, 2, 0, 2},
			[]int{4, 5, 8, 3, 2},
			1,
			100,
			[]int{},
			codes.InvalidArgument,
		}, // Request beyond current epoch.
	} {
		if len(tc.users) != len(tc.profiles) {
			t.Fatalf("len(tc.users) == %v != len(tc.profiles) == %v", len(tc.users), len(tc.profiles))
		}

		env := NewEnv(t)
		defer env.Close(t)
		env.Client.RetryCount = 0

		// Update profiles.
		if err := env.prepareHistory(userInfo, tc.users, tc.profiles); err != nil {
			t.Fatalf("Failed prepareHistory: %v", err)
		}

		startEpoch := int64(1) // beginning of time.
		listCtx := userInfo[tc.listUser].ctx
		listUserID := userInfo[tc.listUser].userID

		// Test history.
		gotHistory, err := env.Client.ListHistory(listCtx, listUserID, startEpoch, tc.end)
		if got, want := grpc.Code(err), tc.err; got != want {
			t.Fatalf("ListHistory(_, %v, %v, %v) failed: %v, want %v", listUserID, startEpoch, tc.end, got, want)
		}

		// Ensure that history has the correct number of profiles.
		if got, want := len(gotHistory), len(tc.wantHistory); got != want {
			t.Fatalf("len(gotHistory)=%v, want %v", got, want)
		}

		// Ensure that history has the correct profiles in the correct
		// order.
		for j := 0; j < len(gotHistory); j++ {
			if got, want := gotHistory[j], createProfile(tc.wantHistory[j]); !reflect.DeepEqual(got, want) {
				t.Errorf("Invalid profile: %v, want %v", got, want)
			}
		}
	}
}

func (e *Env) prepareHistory(userInfo []UserInfo, users []int, profiles []int) error {
	for j := 0; j < len(users); j++ {
		ctx := userInfo[users[j]].ctx
		userID := userInfo[users[j]].userID
		profile := createProfile(profiles[j])
		_, err := e.Client.Update(ctx, userID, profile)
		// The first update response is always a retry.
		if got, want := err, client.ErrRetry; got != want {
			return fmt.Errorf("Update(%v)=(_, %v), want (_, %v)", userID, got, want)
		}
		if err := e.Signer.Sequence(); err != nil {
			return fmt.Errorf("Failed to sequence: %v", err)
		}
		if err := e.Signer.CreateEpoch(); err != nil {
			return fmt.Errorf("Failed to CreateEpoch: %v", err)
		}
	}
	return nil
}

// createProfile creates a dummy profile using the passed tag.
func createProfile(tag int) *tpb.Profile {
	return &tpb.Profile{
		Keys: map[string][]byte{
			fmt.Sprintf("foo%v", tag): []byte(fmt.Sprintf("bar%v", tag)),
		},
	}
}

// TODO: Test AppID filtering when implemented.
