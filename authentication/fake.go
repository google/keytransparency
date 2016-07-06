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

type FakeAuth struct{}

// NewFake returns a new authenticator.
func NewFake() *FakeAuth {
	return &FakeAuth{}
}

// NewContext adds authentication details to a new background context.
func (a *FakeAuth) NewContext(userID string) context.Context {
	md := make(map[string][]string)
	md["userid"] = []string{userID}
	return metadata.NewContext(context.TODO(), md)
}

// ValidateCreds verifies that the requiredUserID is present in ctx.
func (a *FakeAuth) ValidateCreds(ctx context.Context, requiredUserID string) error {
	md, ok := metadata.FromContext(ctx)
	if !ok {
		return ErrMissingAuth
	}
	userIDs, ok := md["userid"]
	if !ok || len(userIDs) != 1 {
		return ErrMissingAuth
	}
	if got, want := md["userid"][0], requiredUserID; got != want {
		log.Printf("auth: wrong user. got: %v, want %v", got, want)
		return ErrWrongUser
	}
	return nil
}
