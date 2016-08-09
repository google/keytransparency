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
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	// AddJSONReq is the request that is being modeled here.
	AddJSONReq  = `{"map_head":{"epoch":1,"root":"EWyr9DFDwaIjVA2Y4BddJ16WndzzwGn4JTQQ87lnkh0=","issue_time":{"seconds":2}},"signatures":{"6efc5bec":{"hash_algorithm":4,"sig_algorithm":3,"signature":"MEUCIAK5nqVdru/7xXUohD1R23wGX07pvh9eCVKgzVBXzpw0AiEA0G91bHKxGm5TaPQgR5sReVyYAOYaS9WhQCV4rXMQc3M="}}}`
	addJSONResp = `{ "sct_version": 0, "id": "3xwuwRUAlFJHqWFoMl3cXHlZ6PfG04j8AC4LvT9012Q=", "timestamp": 1469661431992, "extensions": "", "signature": "BAMARjBEAiBRH\/bZrc4Fl6B6pTWsj0vo9elzbWzgpDKpczEod4pRDwIga03DUchNDRWwtv2xHi7v9kzestFGkEpyMn1jYTsk9nc=" }`
	getSTHResp  = `{ "tree_size": 13, "timestamp": 1469662018234, "sha256_root_hash": "R9WC7p\/bRdY\/66oy3quY\/0Mt6cjQFyoBZsetEx0IX+M=", "tree_head_signature": "BAMARzBFAiEA7KhfIJPzLC0TW8+GqICSXEvjDFja4UvuB95qJwlrhC0CIEAi1T5ZM5hz\/OWWWsekPk9UxOpvVy63fEzbocE4rIjD" }`
	// LeafHash should be the leafhash of AddJSONReq
	LeafHash = `KVp7ZE6jlFOHhYJassBbPzlw0aehUxNpC%2FiY57%2B1ZbU%3D`
	// curl 'http://localhost:8088/ct/v1/get-proof-by-hash?tree_size=13&hash=KVp7ZE6jlFOHhYJassBbPzlw0aehUxNpC%2FiY57%2B1ZbU%3D'
	proofByHashResp = `{ "leaf_index": 9, "audit_path": [ "AWYmKRB\/QfVeQC\/rNwxJgHa4EuqtjhxtcXDcUdzevl8=", "yTCGf34J03ex7inF4sOBVh39vLo\/VYbaQUbmm8Z4Z2c=", "BRBvXBkQgjHjTgcmuysrDr4S\/fHQGAOnElm+i1DE9eY=", "0UUQNaadR+axKIFU064lMXi00aMsKFwTZjvinNskmy8=" ] }`
)

// NewCTServer creates a test CT server.
func NewCTServer(t testing.TB) *httptest.Server {
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/ct/v1/get-sth":
			w.Write([]byte(getSTHResp))
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
