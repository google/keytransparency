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
	"log"

	"golang.org/x/net/context"
	"google.golang.org/grpc/metadata"
)

type BasicAuth struct{}

// New returns a new authenticator.
func New() Authenticator {
	return &BasicAuth{}
}

func (a *BasicAuth) NewContext(userID string, scopes []string) context.Context {
	md := make(map[string][]string)
	md["userid"] = []string{userID}
	md["scopes"] = scopes
	return metadata.NewContext(context.Background(), md)
}

func (a *BasicAuth) ValidateCreds(ctx context.Context, requiredUserID string, requiredScopes []string) bool {
	md, ok := metadata.FromContext(ctx)
	if !ok {
		log.Printf("Failed auth: Context is missing authentication information.")
		return false
	}
	userIDs, ok := md["userid"]
	if !ok || len(userIDs) != 1 {
		log.Printf("Failed auth: Context is missing authentication information.")
		return false
	}
	if got, want := md["userid"][0], requiredUserID; got != want {
		log.Printf("Failed auth: userID: %v, want %v", got, want)
		return false
	}
	set := make(map[string]bool)
	for _, scope := range md["scopes"] {
		set[scope] = true
	}
	for _, scope := range requiredScopes {
		if _, ok := set[scope]; !ok {
			log.Printf("Failed auth: userID: %v missing scope %v", requiredUserID, scope)
			return false
		}
	}
	return true
}
