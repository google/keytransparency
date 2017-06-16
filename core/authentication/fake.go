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
	"fmt"
	"strings"

	"github.com/golang/glog"
	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

const fakeCredentialType string = "FakeCredential"

// NewFake returns a new authenticator.
func NewFake() *FakeAuth {
	return &FakeAuth{}
}

// FakeAuth provides a fake authenticator for testing.
type FakeAuth struct{}

// ValidateCreds verifies that the requiredUserID is present in the authorization metadata of the ctx.
func (a *FakeAuth) ValidateCreds(ctx context.Context, requiredUserID string) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		glog.V(2).Infof("FakeAuth: missing authentication data")
		return ErrMissingAuth
	}
	authHeader, ok := md["authorization"]
	if !ok || len(authHeader) != 1 {
		return ErrMissingAuth
	}
	p := strings.Split(authHeader[0], " ")
	if len(p) != 2 {
		return fmt.Errorf("Bad Authentication Format")
	}

	if got, want := p[0], fakeCredentialType; got != want {
		return fmt.Errorf("FakeAuth: wrong credential type. got: %v, want %v", got, want)
	}

	if got, want := p[1], requiredUserID; got != want {
		glog.V(2).Infof("FakeAuth: wrong user. got: %v, want %v", got, want)
		return ErrWrongUser
	}
	glog.V(2).Infof("FakeAuth: fake authentication suceeded for user %+v", requiredUserID)
	return nil
}

func GetFakeCredential(userID string) credentials.PerRPCCredentials {
	return FakeCredential{userID}
}

type FakeCredential struct {
	userID string
}

func (c FakeCredential) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": fakeCredentialType + " " + c.userID,
	}, nil
}

func (c FakeCredential) RequireTransportSecurity() bool {
	return true
}
