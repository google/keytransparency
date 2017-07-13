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
	"errors"
	"log"
	"strings"

	"github.com/google/keytransparency/core/authentication"

	"net/http"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	gAPI "google.golang.org/api/oauth2/v2"
	"google.golang.org/grpc/metadata"
)

// GRPC stores authentication information in the "authorization" header.

var (
	// E2EScope authorizes a user to change their keys in the keyserver.
	E2EScope = "https://www.googleapis.com/auth/e2ekeys"
	// RequiredScopes is the set of scopes the server requires for a user to change keys.
	RequiredScopes = []string{gAPI.UserinfoEmailScope, E2EScope}

	// ErrBadFormat occurs when the authentication header is malformed.
	ErrBadFormat = errors.New("auth: bad authorization header format")
	// ErrInvalidToken occurs when the authentication header is not valid.
	ErrInvalidToken = errors.New("auth: invalid token")
	// ErrEmailNotVerified occurs when token info indicates that email has not been verified.
	ErrEmailNotVerified = errors.New("auth: unverified email address")
	// ErrMissingScope occurs when a required scope is missing.
	ErrMissingScope = errors.New("auth: missing scope")
)

// GAuth authenticates Google users through the Google TokenInfo API endpoint.
type GAuth struct {
	service *gAPI.Service
}

// NewGoogleAuth creates a new authenticator for Google users.
func NewGoogleAuth() (*GAuth, error) {
	googleService, err := gAPI.New(http.DefaultClient)
	if err != nil {
		return nil, err
	}
	return &GAuth{googleService}, nil
}

// ValidateCreds authenticate the information present in ctx.
func (a *GAuth) ValidateCreds(ctx context.Context) (*authentication.SecurityContext, error) {
	// Get Tokeninfo from credentials.
	tokenInfo, err := a.validateToken(ctx)
	if err != nil {
		return nil, err
	}
	if !tokenInfo.VerifiedEmail {
		return nil, ErrEmailNotVerified
	}

	// Validate scopes.
	scopes := strings.Split(tokenInfo.Scope, " ")
	diff := setDifference(RequiredScopes, scopes)
	if len(diff) > 0 {
		log.Printf("Failed auth: missing scopes %v", diff)
		return nil, ErrMissingScope
	}
	return authentication.NewSecurityContext(tokenInfo.Email), nil
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

// validateToken makes an https request to the tokeninfo API using the access
// token provided in the header.
func (a *GAuth) validateToken(ctx context.Context) (*gAPI.Tokeninfo, error) {
	token, err := getIDTokenAuthorizationHeader(ctx)
	if err != nil {
		return nil, err
	}
	if !token.Valid() {
		return nil, ErrInvalidToken
	}

	infoCall := a.service.Tokeninfo()
	infoCall.AccessToken(token.AccessToken)
	info, err := infoCall.Do()
	if err != nil {
		return nil, err
	}
	return info, nil
}

// getIDTokenAuthorizationHeader pulls the bearer token from the "authorization"
// header in gRPC.
func getIDTokenAuthorizationHeader(ctx context.Context) (*oauth2.Token, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, authentication.ErrMissingAuth
	}
	authHeader, ok := md["authorization"]
	if !ok || len(authHeader) != 1 {
		return nil, authentication.ErrMissingAuth
	}
	p := strings.Split(authHeader[0], " ")
	if len(p) != 2 {
		return nil, ErrBadFormat
	}
	return &oauth2.Token{
		TokenType:   p[0],
		AccessToken: p[1],
	}, nil
}
