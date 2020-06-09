// Copyright 2020 Google Inc. All Rights Reserved.
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

package serverutil

import (
	"net/http"

	"gocloud.dev/server/health"
)

// RootHeaalthHandler handles liveness checks at "/".
// All other requests are passed through to `otherHandler`.
func RootHealthHandler(otherHandler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Capture requests for the root "/" page first.
		// This is the default load balancer health check.
		// https://cloud.google.com/kubernetes-engine/docs/concepts/ingress#health_checks
		if r.URL.Path == "/" {
			health.HandleLive(w, r)
			return
		}
		otherHandler.ServeHTTP(w, r)
	}
}
