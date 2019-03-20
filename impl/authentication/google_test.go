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
	"bytes"
	"context"
	"flag"
	"net/http"
	"reflect"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"golang.org/x/oauth2"
)

var (
	// 1) Get application default credentials:
	// https://developers.google.com/accounts/docs/application-default-credentials

	// 2) Get an Access Token from
	// https://developers.google.com/oauthplayground with scopes:
	// https://www.googleapis.com/auth/userinfo.email,
	// https://www.googleapis.com/auth/e2ekeys
	accessToken = flag.String("token", "", "Access token")
	// 3) Enter the email address used in the above step here:
	email = flag.String("email", "", "Email address")
)

// Example test invocation:
// GOOGLE_APPLICATION_CREDENTIALS=/path/to/server_account.json \
// go test ./authentication/ -token=authentication_token -email=youremail@example.com
func TestGoogleAuthn(t *testing.T) {
	if *accessToken == "" {
		t.Skip()
	}
	ctx := context.Background()
	a, err := NewGoogleAuth(ctx)
	if err != nil {
		t.Fatalf("Failed to create GoogleAuth: %v", err)
	}

	mux := runtime.NewServeMux()

	// Insert token into http request
	r, err := http.NewRequest("", "", bytes.NewBufferString(""))
	if err != nil {
		t.Fatalf("Failed to create http requets: %v", err)
	}
	token := &oauth2.Token{AccessToken: *accessToken, TokenType: "Bearer"}
	token.SetAuthHeader(r)

	// Convert http request into grpc header.
	ctx, err = runtime.AnnotateContext(ctx, mux, r)
	if err != nil {
		t.Errorf("Error annotating context: %v", err)
	}

	sctx, err := a.AuthFunc(ctx)
	if err != nil {
		t.Fatalf("AuthFunc(): %v", err)
	}
	validated, ok := FromContext(sctx)
	if !ok {
		t.Fatalf("FromContext(): no ValidatedSecurity object found")
	}
	if got, want := validated.Email, *email; got != want {
		t.Errorf("validated.Email: %v, want %v", got, want)
	}
}

func TestSetDifference(t *testing.T) {
	for _, tc := range []struct {
		a    []string
		b    []string
		diff []string
	}{
		{[]string{"a", "b"}, []string{"b", "c"}, []string{"a"}},
		{[]string{"a", "b"}, []string{"b", "a"}, []string(nil)},
		{[]string{"a", "b"}, []string{}, []string{"a", "b"}},
	} {
		if got := setDifference(tc.a, tc.b); !reflect.DeepEqual(got, tc.diff) {
			t.Errorf("setDiff(%v, %v): %#v, want %#v", tc.a, tc.b, got, tc.diff)
		}
	}
}
