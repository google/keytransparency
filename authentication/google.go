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

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	google "google.golang.org/api/oauth2/v2"
	"google.golang.org/grpc/metadata"
)

// GRPC stores authentication information in the "authorization" header.

var (
	E2EScope       = "https://www.googleapis.com/auth/e2ekeys"
	RequiredScopes = []string{google.UserinfoEmailScope, E2EScope}

	ErrBadFormat                = errors.New("auth: bad authorization header format")
	ErrNoBearer                 = errors.New("auth: no bearer token found")
	ErrUnableToGetGoogleUser    = errors.New("auth: unable to get google user")
	ErrCannotValidateGoogleUser = errors.New("auth: could not validate google user")
	ErrInvalidToken             = errors.New("auth: invalid token")
	ErrEmailNotVerified         = errors.New("auth: unverified email address")
	ErrMissingScope             = errors.New("auth: missing scope")
)

type OAuth struct {
	config *oauth2.Config
}

func NewGoogleAuth(config *oauth2.Config) Authenticator {
	return &OAuth{config}
}

// ValidateCreds verifies that email is equal to the validated email address
// associated with the access token in the authorization header in ctx.
func (a *OAuth) ValidateCreds(ctx context.Context, email string) error {
	// Get Tokeninfo from credentials.
	tokenInfo, err := a.validateToken(ctx)
	if err != nil {
		return err
	}
	if !tokenInfo.VerifiedEmail {
		return ErrEmailNotVerified
	}

	// Validate email address. TODO: is email canonicalized?
	if got, want := tokenInfo.Email, email; got != want {
		return ErrWrongUser
	}

	// Validate scopes.
	scopes := strings.Split(tokenInfo.Scope, " ")
	diff := setDifference(RequiredScopes, scopes)
	if len(diff) > 0 {
		log.Printf("Failed auth: missing scopes %v", diff)
		return ErrMissingScope
	}
	return nil
}

// setDifference returns all the elements of A that are not elements of B.
func setDifference(a, b []string) []string {
	// Build set b.
	setB := make(map[string]bool)
	for _, e := range b {
		setB[e] = true
	}
	// Iterate through A, adding elements that are not in B.
	diff := make([]string, 0)
	for _, e := range a {
		if _, ok := setB[e]; !ok {
			diff = append(diff, e)
		}
	}
	return diff
}

// validateToken makes an https request to the tokeninfo API using the access
// token provided in the header.
func (a *OAuth) validateToken(ctx context.Context) (*google.Tokeninfo, error) {
	token, err := getIDTokenAuthorizationHeader(ctx)
	if err != nil {
		return nil, err
	}
	if !token.Valid() {
		return nil, ErrInvalidToken
	}

	httpClient := a.config.Client(ctx, token)
	googleService, err := google.New(httpClient)
	if err != nil {
		return nil, err
	}

	info_call := googleService.Tokeninfo()
	info_call.AccessToken(token.AccessToken)
	return info_call.Do()
}

// getIDTokenAuthorizationHeader pulls the bearer token from the "authorization"
// header in gRPC.
func getIDTokenAuthorizationHeader(ctx context.Context) (*oauth2.Token, error) {
	md, ok := metadata.FromContext(ctx)
	if !ok {
		return nil, ErrMissingAuth
	}
	authHeader, ok := md["authorization"]
	if !ok || len(authHeader) != 1 {
		return nil, ErrMissingAuth
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
