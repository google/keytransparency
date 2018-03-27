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
	"fmt"
	"strings"

	"github.com/golang/glog"
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

// ValidateCreds authenticate the information present in ctx.
func (a *FakeAuth) ValidateCreds(ctx context.Context) (*SecurityContext, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		glog.V(2).Infof("FakeAuth: missing authentication data")
		return nil, ErrMissingAuth
	}
	authHeader, ok := md["authorization"]
	if !ok || len(authHeader) != 1 {
		return nil, ErrMissingAuth
	}
	p := strings.Split(authHeader[0], " ")
	if len(p) != 2 {
		return nil, fmt.Errorf("Bad Authentication Format")
	}

	if got, want := p[0], fakeCredentialType; got != want {
		return nil, fmt.Errorf("FakeAuth: wrong credential type. got: %v, want %v", got, want)
	}

	glog.V(2).Infof("FakeAuth: fake authentication succeeded for user %+v", p[1])
	return NewSecurityContext(p[1]), nil
}

// GetFakeCredential returns fake PerRPCCredentials
func GetFakeCredential(userID string) credentials.PerRPCCredentials {
	return fakeCredential{userID}
}

// fakeCredential implements credentials.PerRPCCredentials.
type fakeCredential struct {
	userID string
}

func (c fakeCredential) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": fakeCredentialType + " " + c.userID,
	}, nil
}

func (c fakeCredential) RequireTransportSecurity() bool {
	return true
}

// WithOutgoingFakeAuth returns a ctx with FakeAuth information for userID.
func WithOutgoingFakeAuth(ctx context.Context, userID string) context.Context {
	md, _ := GetFakeCredential(userID).GetRequestMetadata(ctx)
	return metadata.NewOutgoingContext(ctx, metadata.New(md))
}
