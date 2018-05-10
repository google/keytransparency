// Copyright 2018 Google Inc. All Rights Reserved.
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
	"testing"

	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestBasicValidateCreds(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		desc      string
		ctx       context.Context
		wantEmail string
		wantCode  codes.Code
	}{
		{desc: "missing authentication", ctx: ctx, wantCode: codes.Unauthenticated},
		{desc: "working case", ctx: WithOutgoingFakeAuth(ctx, "foo"), wantEmail: "foo"},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			// Convert outgoing context to incoming context.
			inCtx := metautils.ExtractOutgoing(tc.ctx).ToIncoming(ctx)
			sctx, err := FakeAuthFunc(inCtx)
			if got, want := status.Code(err), tc.wantCode; got != want {
				t.Errorf("FakeAuthFunc(): %v, want %v", err, want)
			}
			if err != nil {
				return
			}
			validated, ok := FromContext(sctx)
			if !ok {
				t.Fatalf("FromContext(): no ValidatedSecurity object found")
			}
			if got, want := validated.Email, tc.wantEmail; got != want {
				t.Errorf("validated.Email: %v, want %v", got, want)
			}
		})
	}
}
