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
	"flag"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"

	"github.com/gengo/grpc-gateway/runtime"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	// 1) Create OAuth2 Credentials: https://console.developers.google.com/apis/credentials
	// download the client secrets file, and supply the path as a test argument.
	clientSecretFile = flag.String("oauth", "", "path to client secrets")
	// 2) Get an Access Token from
	// https://developers.google.com/oauthplayground with scopes:
	// https://www.googleapis.com/auth/userinfo.email,
	// https://www.googleapis.com/auth/e2ekeys
	accessToken = flag.String("token", "", "Access token")
	// 3) Enter the email address used in the above step here:
	email = flag.String("email", "", "Email address")
)

func getConfig(t testing.TB) *oauth2.Config {
	b, err := ioutil.ReadFile(*clientSecretFile)
	if err != nil {
		t.Fatalf("Unable to read client secret file: %v", err)
	}
	config, err := google.ConfigFromJSON(b)
	if err != nil {
		t.Fatalf("Unable to parse client secret file to config: %v", err)
	}
	return config
}

func TestGoogleValidateCreds(t *testing.T) {
	if *clientSecretFile == "" {
		t.Skip()
	}
	a := NewGoogleAuth(getConfig(t))

	// Insert token into http request
	r, err := http.NewRequest("", "", bytes.NewBufferString(""))
	if err != nil {
		t.Fatalf("Failed to create http requets: %v", err)
	}
	token := &oauth2.Token{AccessToken: *accessToken, TokenType: "Bearer"}
	token.SetAuthHeader(r)

	// Convert http request into grpc header.
	ctx := context.Background()
	ctx, err = runtime.AnnotateContext(ctx, r)
	if err != nil {
		t.Errorf("Error annotating context: %v", err)
	}

	if err := a.ValidateCreds(ctx, *email); err != nil {
		t.Errorf("ValidateCreds(): %v", err)
	}
}

func TestSetDifference(t *testing.T) {
	tests := []struct {
		a    []string
		b    []string
		diff []string
	}{
		{[]string{"a", "b"}, []string{"b", "c"}, []string{"a"}},
		{[]string{"a", "b"}, []string{"b", "a"}, []string{}},
		{[]string{"a", "b"}, []string{}, []string{"a", "b"}},
	}
	for _, tc := range tests {
		if got := setDifference(tc.a, tc.b); !reflect.DeepEqual(got, tc.diff) {
			t.Errorf("setDiff(%v, %v): %v, want %v", tc.a, tc.b, got, tc.diff)
		}
	}
}
