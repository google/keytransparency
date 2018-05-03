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

// Package authorization contains the authorization module implementation.
package authorization

import (
	"testing"

	"github.com/google/keytransparency/core/authentication"

	authzpb "github.com/google/keytransparency/core/api/type/type_go_proto"
	pb "github.com/google/keytransparency/impl/authorization/authz_go_proto"
)

const (
	testUser = "user@example.com"
	l1       = "r1"
	l2       = "r2"
	l3       = "r3"
	l4       = "r4"
	l5       = "r5"
	admin1   = "admin1@example.com"
	admin2   = "admin2@example.com"
	admin3   = "admin3@example.com"
	admin4   = "admin4@example.com"
	res1     = "1|1"
	res2     = "1|2"
	res3     = "1|3"
	res4     = "1|4"
)

func setup() *authz {
	a := &authz{}
	a.policy = &pb.AuthorizationPolicy{
		Roles: map[string]*pb.AuthorizationPolicy_Role{
			l1: {
				Principals: []string{admin1},
				Permissions: []authzpb.Permission{
					authzpb.Permission_WRITE,
				},
			},
			l2: {
				Principals: []string{admin1, admin2},
				Permissions: []authzpb.Permission{
					authzpb.Permission_LOG,
					authzpb.Permission_READ,
				},
			},
			l3: {
				Principals: []string{admin3},
				Permissions: []authzpb.Permission{
					authzpb.Permission_LOG,
				},
			},
			l4: {},
		},
		ResourceToRoleLabels: map[string]*pb.AuthorizationPolicy_RoleLabels{
			res1: {
				Labels: []string{l1, l2},
			},
			res2: {
				Labels: []string{l3},
			},
			res3: {
				Labels: []string{l4},
			},
			res4: {
				Labels: []string{l5},
			},
		},
	}
	return a
}

func TestIsAuthorized(t *testing.T) {
	a := setup()
	for _, tc := range []struct {
		description string
		sctx        *authentication.SecurityContext
		domainID    string
		appID       string
		userID      string
		permission  authzpb.Permission
		success     bool
	}{
		{
			"self updating own profile",
			authentication.NewSecurityContext(testUser),
			"1",
			"1",
			testUser,
			authzpb.Permission_WRITE,
			true,
		},
		{
			"other accessing profile, authorized with one role",
			authentication.NewSecurityContext(admin1),
			"1",
			"1",
			"",
			authzpb.Permission_WRITE,
			true,
		},
		{
			"other accessing profile, authorized with multiple roles",
			authentication.NewSecurityContext(admin2),
			"1",
			"1",
			"",
			authzpb.Permission_READ,
			true,
		},
		{
			"other accessing profile, authorized second resource",
			authentication.NewSecurityContext(admin3),
			"1",
			"2",
			"",
			authzpb.Permission_LOG,
			true,
		},
		{
			"not authorized, no resource label",
			authentication.NewSecurityContext(admin1),
			"1",
			"10",
			"",
			authzpb.Permission_WRITE,
			false,
		},
		{
			"not authorized, no label_to_role defined",
			authentication.NewSecurityContext(admin1),
			"1",
			"4",
			"",
			authzpb.Permission_LOG,
			false,
		},
		{
			"not authorized, empty role definition",
			authentication.NewSecurityContext(admin1),
			"1",
			"3",
			"",
			authzpb.Permission_WRITE,
			false,
		},
		{
			"not authorized, wrong permission",
			authentication.NewSecurityContext(admin2),
			"1",
			"1",
			"",
			authzpb.Permission_WRITE,
			false,
		},
		{
			"not authorized principal",
			authentication.NewSecurityContext(admin4),
			"1",
			"1",
			"",
			authzpb.Permission_WRITE,
			false,
		},
	} {
		err := a.IsAuthorized(tc.sctx, tc.domainID, tc.appID, tc.userID, tc.permission)
		if got, want := err == nil, tc.success; got != want {
			t.Errorf("%v: IsAuthorized err == nil: %v, want %v", tc.description, got, want)
		}
	}
}

func TestResouceLabel(t *testing.T) {
	for _, tc := range []struct {
		domainID string
		appID    string
		out      string
	}{
		{"1", "1", "1|1"},
		{"1", "2", "1|2"},
		{"1", "111", "1|111"},
		{"111", "1", "111|1"},
		{"111", "111", "111|111"},
	} {
		if got, want := resourceLabel(tc.domainID, tc.appID), tc.out; got != want {
			t.Errorf("resourceLabel(%v, %v)=%v, want %v", tc.domainID, tc.appID, got, want)
		}
	}
}

func TestIsPermisionInRole(t *testing.T) {
	// AuthorizationPolicy_Role.Principals is not relevant in this test.
	for _, tc := range []struct {
		description string
		role        *pb.AuthorizationPolicy_Role
		permission  authzpb.Permission
		out         bool
	}{
		{
			"permission is not in role, empty permissions list",
			&pb.AuthorizationPolicy_Role{
				Principals:  []string{},
				Permissions: []authzpb.Permission{},
			},
			authzpb.Permission_WRITE,
			false,
		},
		{
			"permission is not in role, permission not found",
			&pb.AuthorizationPolicy_Role{
				Principals: []string{},
				Permissions: []authzpb.Permission{
					authzpb.Permission_LOG,
					authzpb.Permission_READ,
				},
			},
			authzpb.Permission_WRITE,
			false,
		},
		{
			"permission is in role, one permission in the list",
			&pb.AuthorizationPolicy_Role{
				Principals: []string{},
				Permissions: []authzpb.Permission{
					authzpb.Permission_LOG,
					authzpb.Permission_READ,
				},
			},
			authzpb.Permission_LOG,
			true,
		},
		{
			"permission is in role, multiple permissions in the list",
			&pb.AuthorizationPolicy_Role{
				Principals: []string{},
				Permissions: []authzpb.Permission{
					authzpb.Permission_LOG,
					authzpb.Permission_READ,
					authzpb.Permission_WRITE,
				},
			},
			authzpb.Permission_WRITE,
			true,
		},
	} {
		if got, want := isPermisionInRole(tc.role, tc.permission), tc.out; got != want {
			t.Errorf("%v: isPermisionInRole=%v, want %v", tc.description, got, want)
		}
	}
}
