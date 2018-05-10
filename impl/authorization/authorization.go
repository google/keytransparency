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
	"context"
	"fmt"
	"strings"

	"github.com/google/keytransparency/core/authorization"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authzpb "github.com/google/keytransparency/core/api/type/type_go_proto"
	"github.com/google/keytransparency/impl/authentication"
	pb "github.com/google/keytransparency/impl/authorization/authz_go_proto"
)

type authz struct {
	policy *pb.AuthorizationPolicy
}

// New creates a new instance of the authorization module.
func New() authorization.Authorization {
	return &authz{}
}

// Authorize verifies that the identity issuing the call.
// ctx must contain an authentication.SecurityContext.
// A call is authorized if:
//  1. userID matches SecurityContext.Email,
//  2. or, SecurityContext.Email is authorized to do the action in domains/domainID/apps/appID.
func (a *authz) Authorize(ctx context.Context,
	domainID, appID, userID string, permission authzpb.Permission) error {
	sctx, ok := authentication.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "Request does not contain a ValidatedSecurity object")
	}

	// Case 1.
	if sctx.Email == userID {
		return nil
	}

	// Case 2.
	rLabel := resourceLabel(domainID, appID)
	roles, ok := a.policy.GetResourceToRoleLabels()[rLabel]
	if !ok {
		return status.Errorf(codes.PermissionDenied, "%v does not have a defined policy", rLabel)
	}
	for _, l := range roles.GetLabels() {
		role := a.policy.GetRoles()[l]
		if isPrincipalInRole(role, sctx.Email) && isPermisionInRole(role, permission) {
			return nil
		}
	}
	return status.Errorf(codes.PermissionDenied, "%v is not authorized to perform %v on %v", sctx.Email, permission, rLabel)
}

func resourceLabel(domainID, appID string) string {
	return fmt.Sprintf("domains/%v/apps/%v",
		strings.Replace(domainID, "/", "_", -1),
		strings.Replace(appID, "/", "_", -1))
}

func isPrincipalInRole(role *pb.AuthorizationPolicy_Role, identity string) bool {
	for _, p := range role.GetPrincipals() {
		if p == identity {
			return true
		}
	}
	return false
}

func isPermisionInRole(role *pb.AuthorizationPolicy_Role, permission authzpb.Permission) bool {
	for _, p := range role.GetPermissions() {
		if p == permission {
			return true
		}
	}
	return false
}
