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

package hammer

import (
	"context"
)

// ReqHandler executes a request.
type ReqHandler func(ctx context.Context, req *request) error

type request struct {
	UserIDs   []string
	BatchSize int
}

func startHandlers(ctx context.Context, inflightReqs <-chan request, reqHandlers []ReqHandler) {
	go func() {
		for _, rh := range reqHandlers {
			go func(rh ReqHandler) {
				for req := range inflightReqs {
					rh(ctx, &req)
				}
			}(rh)
		}
	}()
}
