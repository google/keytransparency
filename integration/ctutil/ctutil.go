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

// Package ctutil implements helper functions for testing against Certificate Transparency.
package ctutil

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	validSTHResponse = `{"tree_size":3721782,"timestamp":1396609800587,
        "sha256_root_hash":"SxKOxksguvHPyUaKYKXoZHzXl91Q257+JQ0AUMlFfeo=",
        "tree_head_signature":"BAMARjBEAiBUYO2tODlUUw4oWGiVPUHqZadRRyXs9T2rSXchA79VsQIgLASkQv3cu4XdPFCZbgFkIUefniNPCpO3LzzHX53l+wg="}`
	validSTHResponseTreeSize          = 3721782
	validSTHResponseTimestamp         = 1396609800587
	validSTHResponseSHA256RootHash    = "SxKOxksguvHPyUaKYKXoZHzXl91Q257+JQ0AUMlFfeo="
	validSTHResponseTreeHeadSignature = "BAMARjBEAiBUYO2tODlUUw4oWGiVPUHqZadRRyXs9T2rSXchA79VsQIgLASkQv3cu4XdPFCZbgFkIUefniNPCpO3LzzHX53l+wg="
	addJSONResp                       = `{  
	   "sct_version":0,
	   "id":"KHYaGJAn++880NYaAY12sFBXKcenQRvMvfYE9F1CYVM=",
	   "timestamp":1337,
	   "extensions":"",
	   "signature":"BAMARjBEAiAIc21J5ZbdKZHw5wLxCP+MhBEsV5+nfvGyakOIv6FOvAIgWYMZb6Pw///uiNM7QTg2Of1OqmK1GbeGuEl9VJN8v8c="
	}`
	proofByHashResp = `
	{
		"leaf_index": 3,
		"audit_path": [
		"pMumx96PIUB3TX543ljlpQ/RgZRqitRfykupIZrXq0Q=",
		"5s2NQWkjmesu+Kqgp70TCwVLwq8obpHw/JyMGwN56pQ=",
		"7VelXijfmGFSl62BWIsG8LRmxJGBq9XP8FxmszuT2Cg="
		]
	}`
)

// NewCTServer creates a test CT server.
func NewCTServer(t testing.TB) *httptest.Server {
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/ct/v1/get-sth":
			fmt.Fprintf(w, `{"tree_size": %d, "timestamp": %d, "sha256_root_hash": "%s", "tree_head_signature": "%s"}`,
				validSTHResponseTreeSize,
				int64(validSTHResponseTimestamp),
				validSTHResponseSHA256RootHash,
				validSTHResponseTreeHeadSignature)

		case r.URL.Path == "/ct/v1/add-json":
			w.Write([]byte(addJSONResp))
		case r.URL.Path == "/ct/v1/get-proof-by-hash":
			w.Write([]byte(proofByHashResp))
		default:
			t.Fatalf("Incorrect URL path: %s", r.URL.Path)
		}
	}))
	return hs
}
