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

	"github.com/google/keytransparency/impl/authentication"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	authzpb "github.com/google/keytransparency/impl/authorization/authz_go_proto"
)

// AuthzFunc performs authorization using the embedded SecurityContext on a message.
type AuthzFunc func(context.Context, interface{}) error

// AuthzPolicy contains the authorization policy.
type AuthzPolicy struct {
	Policy *authzpb.AuthorizationPolicy
}

// Authorize verifies that the identity issuing the call.
// ctx must contain an authentication.SecurityContext.
// A call is authorized if:
//  1. userID matches SecurityContext.Email,
//  2. or, SecurityContext.Email is authorized to do the action in directories/directoryID.
func (a *AuthzPolicy) Authorize(ctx context.Context, m interface{}) error {
	sctx, ok := authentication.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "Request does not contain a ValidatedSecurity object")
	}

	switch t := m.(type) {
	case *pb.UpdateEntryRequest:
		return a.checkPermission(sctx, t.DirectoryId, t.EntryUpdate.UserId)
		// Can't authorize any other requests
	default:
		return status.Errorf(codes.PermissionDenied, "message type %T not recognized", t)
	}
}

func (a *AuthzPolicy) checkPermission(sctx *authentication.SecurityContext, directoryID, userID string) error {
	// Case 1.
	if sctx.Email == userID {
		return nil
	}

	// Case 2.
	rLabel, err := resourceLabel(directoryID)
	if err != nil {
		return err
	}
	roles, ok := a.Policy.GetResourceToRoleLabels()[rLabel]
	if !ok {
		return status.Errorf(codes.PermissionDenied, "%v does not have a defined policy", rLabel)
	}
	for _, l := range roles.GetLabels() {
		role := a.Policy.GetRoles()[l]
		if isPrincipalInRole(role, sctx.Email) {
			return nil
		}
	}
	return status.Errorf(codes.PermissionDenied, "%v is not authorized to act on %v", sctx.Email, rLabel)
}

func resourceLabel(directoryID string) (string, error) {
	if strings.Contains(directoryID, "/") {
		return "", status.Errorf(codes.InvalidArgument, "resource label contains invalid character '/'")
	}
	return fmt.Sprintf("directories/%v", directoryID), nil
}

func isPrincipalInRole(role *authzpb.AuthorizationPolicy_Role, identity string) bool {
	for _, p := range role.GetPrincipals() {
		if p == identity {
			return true
		}
	}
	return false
}
