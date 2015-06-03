// Copyright 2015 Google Inc. All Rights Reserved.
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

package google_security_e2ekeys_v1

import (
	"encoding/json"
	"net/http"

	context "golang.org/x/net/context"
	v2pb "github.com/google/key-server-transparency/proto/v2"
)

// TODO: I wish this could be code generated.
func GetUser_Handler(srv interface{}, ctx context.Context, w http.ResponseWriter, r *http.Request) {
	// Json -> Proto.
	// TODO: insert url params.
	in := new(v2pb.GetUserRequest)
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&in)
	if err != nil {
		http.Error(w, "Error", http.StatusInternalServerError)
	}

	resp, err := srv.(E2EKeyProxyServer).GetUser(ctx, in)
	if err != nil {
		// TODO: Convert error into HTTP status code.
		http.Error(w, "Error", http.StatusInternalServerError)
		return
	}
	// proto -> json
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.Encode(resp)
}
