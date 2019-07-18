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

package authentication

import (
	"context"
	"log"
	"strings"

	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	gAPI "google.golang.org/api/oauth2/v2"
)

// GRPC stores authentication information in the "authorization" header.

var (
	// E2EScope authorizes a user to change their keys in the keyserver.
	E2EScope = "https://www.googleapis.com/auth/e2ekeys"
	// RequiredScopes is the set of scopes the server requires for a user to change keys.
	RequiredScopes = []string{gAPI.UserinfoEmailScope, E2EScope}
)

// GAuth authenticates Google users through the Google TokenInfo API endpoint.
type GAuth struct {
	service *gAPI.Service
}

// NewGoogleAuth creates a new authenticator for Google users.
func NewGoogleAuth(ctx context.Context) (*GAuth, error) {
	googleService, err := gAPI.NewService(ctx)
	if err != nil {
		return nil, err
	}
	return &GAuth{service: googleService}, nil
}

// AuthFunc authenticate the information present in ctx.
func (a *GAuth) AuthFunc(ctx context.Context) (context.Context, error) {
	token, err := parseToken(ctx)
	if err != nil {
		return nil, err
	}
	tokenInfo, err := a.validateToken(token)
	if err != nil {
		return nil, err
	}
	if !tokenInfo.VerifiedEmail {
		return nil, status.Error(codes.Unauthenticated, "auth: unverified email address")
	}

	// Validate scopes.
	scopes := strings.Split(tokenInfo.Scope, " ")
	diff := setDifference(RequiredScopes, scopes)
	if len(diff) > 0 {
		log.Printf("Failed auth: missing scopes %v", diff)
		return nil, status.Error(codes.Unauthenticated, "auth: missing scope")
	}
	return context.WithValue(ctx, securityContextKey, &SecurityContext{
		Email: tokenInfo.Email,
	}), nil
}

// setDifference returns all the elements of A that are not elements of B.
func setDifference(a, b []string) []string {
	// Build set b.
	setB := make(map[string]bool)
	for _, e := range b {
		setB[e] = true
	}
	// Iterate through A, adding elements that are not in B.
	var diff []string
	for _, e := range a {
		if _, ok := setB[e]; !ok {
			diff = append(diff, e)
		}
	}
	return diff
}

func parseToken(ctx context.Context) (*oauth2.Token, error) {
	accessToken, err := grpc_auth.AuthFromMD(ctx, "bearer")
	if err != nil {
		return nil, err
	}
	return &oauth2.Token{
		TokenType:   "bearer",
		AccessToken: accessToken,
	}, nil
}

// validateToken makes an https request to the tokeninfo API using the access
// token provided in the header.
func (a *GAuth) validateToken(token *oauth2.Token) (*gAPI.Tokeninfo, error) {
	if !token.Valid() {
		return nil, status.Error(codes.Unauthenticated, "auth: invalid token")
	}

	infoCall := a.service.Tokeninfo()
	infoCall.AccessToken(token.AccessToken)
	info, err := infoCall.Do()
	if err != nil {
		return nil, err
	}
	return info, nil
}
