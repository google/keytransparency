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

import "context"

// ValidatedSecurity is the auth value stored in the Contexts.
// To obtain a ValidatedSecurity, use an authentication scheme.
type ValidatedSecurity struct {
	Email string
}

// securityContextKey identifies ValidatedSecurity within context.Context.
var securityContextKey struct{}

// FromContext returns a ValidatedSecurity from the current context.
// ValidatedSecurity is inserted into ctx by AuthFunc.
func FromContext(ctx context.Context) (*ValidatedSecurity, bool) {
	v, ok := ctx.Value(securityContextKey).(*ValidatedSecurity)
	return v, ok
}
