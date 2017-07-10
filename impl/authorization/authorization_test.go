package authorization

import (
	"testing"

	"github.com/google/keytransparency/core/authentication"

	authzpb "github.com/google/keytransparency/core/proto/authorization"
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
	roles1 := &authzpb.AuthorizationPolicy_Roles{
		Labels: []string{l1, l2},
	}
	roles2 := &authzpb.AuthorizationPolicy_Roles{
		Labels: []string{l3},
	}
	roles3 := &authzpb.AuthorizationPolicy_Roles{
		Labels: []string{l4},
	}
	roles4 := &authzpb.AuthorizationPolicy_Roles{
		Labels: []string{l5},
	}
	role1 := &authzpb.AuthorizationPolicy_Role{
		Principals: []string{admin1},
		Permissions: []authzpb.Permission{
			authzpb.Permission_WRITE,
		},
	}
	role2 := &authzpb.AuthorizationPolicy_Role{
		Principals: []string{admin1, admin2},
		Permissions: []authzpb.Permission{
			authzpb.Permission_LOG,
			authzpb.Permission_READ,
		},
	}
	role3 := &authzpb.AuthorizationPolicy_Role{
		Principals: []string{admin3},
		Permissions: []authzpb.Permission{
			authzpb.Permission_LOG,
		},
	}
	role4 := &authzpb.AuthorizationPolicy_Role{}

	a := &authz{}
	a.policy = &authzpb.AuthorizationPolicy{
		LabelToRole: map[string]*authzpb.AuthorizationPolicy_Role{
			l1: role1,
			l2: role2,
			l3: role3,
			l4: role4,
		},
		ResourceToRoles: map[string]*authzpb.AuthorizationPolicy_Roles{
			res1: roles1,
			res2: roles2,
			res3: roles3,
			res4: roles4,
		},
	}
	return a
}

func TestIsAuthorized(t *testing.T) {
	a := setup()
	for _, tc := range []struct {
		description string
		sctx        *authentication.SecurityContext
		mapID       int64
		appID       int64
		userID      string
		permission  authzpb.Permission
		success     bool
	}{
		{
			"self updating own profile",
			authentication.NewSecurityContext(testUser),
			1,
			1,
			testUser,
			authzpb.Permission_WRITE,
			true,
		},
		{
			"other accessing profile, authorized with one role",
			authentication.NewSecurityContext(admin1),
			1,
			1,
			"",
			authzpb.Permission_WRITE,
			true,
		},
		{
			"other accessing profile, authorized with multiple roles",
			authentication.NewSecurityContext(admin2),
			1,
			1,
			"",
			authzpb.Permission_READ,
			true,
		},
		{
			"other accessing profile, authorized second resource",
			authentication.NewSecurityContext(admin3),
			1,
			2,
			"",
			authzpb.Permission_LOG,
			true,
		},
		{
			"not authorized, no resource label",
			authentication.NewSecurityContext(admin1),
			1,
			10,
			"",
			authzpb.Permission_WRITE,
			false,
		},
		{
			"not authorized, no label_to_role defined",
			authentication.NewSecurityContext(admin1),
			1,
			4,
			"",
			authzpb.Permission_LOG,
			false,
		},
		{
			"not authorized, empty role definition",
			authentication.NewSecurityContext(admin1),
			1,
			3,
			"",
			authzpb.Permission_WRITE,
			false,
		},
		{
			"not authorized, wrong permission",
			authentication.NewSecurityContext(admin2),
			1,
			1,
			"",
			authzpb.Permission_WRITE,
			false,
		},
		{
			"not authorized principal",
			authentication.NewSecurityContext(admin4),
			1,
			1,
			"",
			authzpb.Permission_WRITE,
			false,
		},
	} {
		err := a.IsAuthorized(tc.sctx, tc.mapID, tc.appID, tc.userID, tc.permission)
		if got, want := err == nil, tc.success; got != want {
			t.Errorf("%v: IsAuthorized err == nil: %v, want %v", tc.description, got, want)
		}
	}
}

func TestResouceLabel(t *testing.T) {
	for _, tc := range []struct {
		mapID int64
		appID int64
		out   string
	}{
		{1, 1, "1|1"},
		{1, 2, "1|2"},
		{1, 111, "1|111"},
		{111, 1, "111|1"},
		{111, 111, "111|111"},
	} {
		if got, want := resourceLabel(tc.mapID, tc.appID), tc.out; got != want {
			t.Errorf("resourceLabel(%v, %v)=%v, want %v", tc.mapID, tc.appID, got, want)
		}
	}
}

func TestPermitted(t *testing.T) {
	// AuthorizationPolicy_Role.Principals is not relevant in this test.
	for _, tc := range []struct {
		description string
		role        *authzpb.AuthorizationPolicy_Role
		permission  authzpb.Permission
		out         bool
	}{
		{
			"not permitted, empty permissions list",
			&authzpb.AuthorizationPolicy_Role{
				Principals:  []string{},
				Permissions: []authzpb.Permission{},
			},
			authzpb.Permission_WRITE,
			false,
		},
		{
			"not permitted, permission not found",
			&authzpb.AuthorizationPolicy_Role{
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
			"permitted, one permission in the list",
			&authzpb.AuthorizationPolicy_Role{
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
			"permitted, multiple permissions in the list",
			&authzpb.AuthorizationPolicy_Role{
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
		if got, want := permitted(tc.role, tc.permission), tc.out; got != want {
			t.Errorf("%v: permitted=%v, want %v", tc.description, got, want)
		}
	}
}
