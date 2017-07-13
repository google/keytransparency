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
	"fmt"

	"github.com/google/keytransparency/core/authentication"
	"github.com/google/keytransparency/core/authorization"

	authzpb "github.com/google/keytransparency/core/proto/authorization"
)

type authz struct {
	policy *authzpb.AuthorizationPolicy
}

// New creates a new instance of the authorization module.
func New() authorization.Authorization {
	return &authz{}
}

// IsAuthorized verifies that the identity issuing the call (from ctx) is
// authorized to carry the given permission. A call is authorized if:
//  1. userID matches the identity in sctx,
//  2. or, sctx's identity is authorized to do the action in mapID and appID.
func (a *authz) IsAuthorized(sctx *authentication.SecurityContext, mapID int64,
	appID, userID string, permission authzpb.Permission) error {
	// Case 1.
	if sctx.Identity() == userID {
		return nil
	}

	// Case 2.
	rLabel := resourceLabel(mapID, appID)
	roles, ok := a.policy.GetResourceToRoleLabels()[rLabel]
	if !ok {
		return fmt.Errorf("resource <mapID=%v, appID=%v> does not have a defined policy", mapID, appID)
	}
	for _, l := range roles.GetLabels() {
		role := a.policy.GetRoles()[l]
		if isPrincipalInRole(role, sctx.Identity()) && isPermisionInRole(role, permission) {
			return nil
		}
	}
	return fmt.Errorf("%v is not authorized to perform %v on resource defined by <mapID=%v, appID=%v>", sctx.Identity(), permission, mapID, appID)
}

func resourceLabel(mapID int64, appID string) string {
	return fmt.Sprintf("%d|%s", mapID, appID)
}

func isPrincipalInRole(role *authzpb.AuthorizationPolicy_Role, identity string) bool {
	for _, p := range role.GetPrincipals() {
		if p == identity {
			return true
		}
	}
	return false
}

func isPermisionInRole(role *authzpb.AuthorizationPolicy_Role, permission authzpb.Permission) bool {
	for _, p := range role.GetPermissions() {
		if p == permission {
			return true
		}
	}
	return false
}
