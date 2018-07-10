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
	"sync"

	"github.com/golang/glog"
)

// ReqHandler executes a request.
type ReqHandler func(ctx context.Context, arg *reqArgs) error

type reqArgs struct {
	UserIDs  []string
	PageSize int
}

func executeRequests(ctx context.Context, inflightReqs <-chan reqArgs, reqHandlers []ReqHandler) {
	var wg sync.WaitGroup
	for _, rh := range reqHandlers {
		wg.Add(1)
		go func(rh ReqHandler) {
			defer wg.Done()
			for req := range inflightReqs {
				if err := rh(ctx, &req); err != nil {
					glog.Errorf("Handler(%v): %v", req, err)
				}
			}
		}(rh)
	}
	wg.Wait()
}
