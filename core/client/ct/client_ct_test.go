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
package ct

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	ct "github.com/google/certificate-transparency/go"
	logclient "github.com/google/certificate-transparency/go/client"

	"github.com/google/key-transparency/core/proto/ctmap"
)

const (
	addJSONReq  = `{"map_head":{"epoch":1,"root":"EWyr9DFDwaIjVA2Y4BddJ16WndzzwGn4JTQQ87lnkh0=","issue_time":{"seconds":2}},"signatures":{"6efc5bec":{"hash_algorithm":4,"sig_algorithm":3,"signature":"MEUCIAK5nqVdru/7xXUohD1R23wGX07pvh9eCVKgzVBXzpw0AiEA0G91bHKxGm5TaPQgR5sReVyYAOYaS9WhQCV4rXMQc3M="}}}`
	addJSONResp = `{ "sct_version": 0, "id": "3xwuwRUAlFJHqWFoMl3cXHlZ6PfG04j8AC4LvT9012Q=", "timestamp": 1469661431992, "extensions": "", "signature": "BAMARjBEAiBRH\/bZrc4Fl6B6pTWsj0vo9elzbWzgpDKpczEod4pRDwIga03DUchNDRWwtv2xHi7v9kzestFGkEpyMn1jYTsk9nc=" }`
	getSTHResp  = `{ "tree_size": 13, "timestamp": 1469662018234, "sha256_root_hash": "R9WC7p\/bRdY\/66oy3quY\/0Mt6cjQFyoBZsetEx0IX+M=", "tree_head_signature": "BAMARzBFAiEA7KhfIJPzLC0TW8+GqICSXEvjDFja4UvuB95qJwlrhC0CIEAi1T5ZM5hz\/OWWWsekPk9UxOpvVy63fEzbocE4rIjD" }`
	leafHash    = `KVp7ZE6jlFOHhYJassBbPzlw0aehUxNpC%2FiY57%2B1ZbU%3D`
	// curl 'http://localhost:8088/ct/v1/get-proof-by-hash?tree_size=13&hash=KVp7ZE6jlFOHhYJassBbPzlw0aehUxNpC%2FiY57%2B1ZbU%3D'
	proofByHashResp = `{ "leaf_index": 9, "audit_path": [ "AWYmKRB\/QfVeQC\/rNwxJgHa4EuqtjhxtcXDcUdzevl8=", "yTCGf34J03ex7inF4sOBVh39vLo\/VYbaQUbmm8Z4Z2c=", "BRBvXBkQgjHjTgcmuysrDr4S\/fHQGAOnElm+i1DE9eY=", "0UUQNaadR+axKIFU064lMXi00aMsKFwTZjvinNskmy8=" ] }`
	pem             = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmXg8sUUzwBYaWrRb+V0IopzQ6o3U
yEJ04r5ZrRXGdpYM8K+hB0pXrGRLI0eeWz+3skXrS0IO83AhA3GpRL6s6w==
-----END PUBLIC KEY-----`
)

// NewCTServer creates a test CT server.
func NewCTServer(t testing.TB) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ct/v1/get-sth":
			w.Write([]byte(getSTHResp))
		case "/ct/v1/add-json":
			w.Write([]byte(addJSONResp))
		case "/ct/v1/get-proof-by-hash":
			w.Write([]byte(proofByHashResp))
		default:
			t.Fatalf("Incorrect URL path: %s", r.URL.Path)
		}
	}))
}

func TestInclusionProof(t *testing.T) {
	hs := NewCTServer(t)
	defer hs.Close()
	l, err := NewLogVerifier([]byte(pem), hs.URL)
	if err != nil {
		t.Fatalf("Failed to create log client: %v", err)
	}
	lnoconn, err := NewLogVerifier([]byte(pem), "")
	if err != nil {
		t.Fatalf("Failed to create log client: %v", err)
	}
	var smh ctmap.SignedMapHead
	if err := json.Unmarshal([]byte(addJSONReq), &smh); err != nil {
		t.Errorf("Error decoding SMH: %v", err)
	}
	sth, err := l.ctlog.GetSTH()
	if err != nil {
		t.Fatalf("Failed to get STH: %v", err)
	}
	sct, err := l.ctlog.AddJSON(&smh)
	if err != nil {
		t.Fatalf("Failed to get SCT from AddJSON: %v", err)
	}

	for _, tc := range []struct {
		l    *Log
		smh  ctmap.SignedMapHead
		want bool
	}{
		{l, smh, true},
		{lnoconn, smh, false},             // Network error
		{l, ctmap.SignedMapHead{}, false}, // Incorrect proof
	} {
		err := tc.l.inclusionProof(sth, &tc.smh, sct.Timestamp)
		if got := err == nil; got != tc.want {
			t.Errorf("inclusionProof: %v, want %v", err, tc.want)
		}
	}
}

func TestUpdateSTH(t *testing.T) {
	l, err := NewLogVerifier([]byte(pem), "")
	if err != nil {
		t.Fatalf("NewLogVerifier(): %v", err)
	}
	for i, tc := range []struct {
		start, end uint64
		sth, proof string
	}{
		{0, 27,
			`{ "tree_size": 27, "timestamp": 1470345452317, "sha256_root_hash": "i8FlAhMYMBQqbGjsoTd5ETyzZB88r86PPweCYAWz1go=", "tree_head_signature": "BAMASDBGAiEAg\/Ew+UzZuVMPmaTgq3l9rv0aXqGa1yNqk04gBVc3ArwCIQDyJiKfH6i8qZGWVcCJrm4ZZoEY0FoGKJCRwmj4AlTpew==" }`,
			"",
		},
		{27, 28,
			`{ "tree_size": 28, "timestamp": 1470350032568, "sha256_root_hash": "bM81peaPCkdbGrVfS55V4tGYKnYvjyDkqNCOfTUWfIM=", "tree_head_signature": "BAMASDBGAiEA9VpA5s2XNI9FeO9i\/q7WN5ehDw1IeNJwA\/1aL2s00o8CIQDnJGZuaCVyRRvQ\/e3Bn\/\/RekMbo3iFq+P2ecCsqiclCQ==" }`,
			`{ "consistency": [ "t0A8H7hDbMSFIYZSaez\/JxZhhuCySpUvz4iw6RpECO0=", "z6OXtl3FHCwSIDfNAwj\/5HY\/vXMgN5u3Y2LlfWmrHgY=", "grgSU6rjELf4Dff+LJ\/AjdgFt2SW85KW+Qfx3i9LSRk=", "BYB0BDK4jX6UPmSboGtIUMe9SwqLaJe6X0BkSWXCGOc=", "t9rD1TCqf2B1s8z15+fPmkRe1JVvjf2VNPhRzt\/m8nM=" ] }`,
		},
	} {
		hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/ct/v1/get-sth":
				w.Write([]byte(tc.sth))
			case "/ct/v1/get-sth-consistency":
				w.Write([]byte(tc.proof))
			default:
				t.Errorf("Incorrect URL path: %s", r.URL.Path)
			}
		}))
		l.ctlog = logclient.New(hs.URL, nil)
		if got := l.STH.TreeSize; got != tc.start {
			t.Errorf("%v: Start TreeSize: %v, want %v", i, got, tc.start)
		}
		if err := l.UpdateSTH(); err != nil {
			t.Errorf("UpdateSTH(): %v", err)
		}
		if got := l.STH.TreeSize; got != tc.end {
			t.Errorf("End TreeSize: %v, want %v", got, tc.end)
		}
		hs.Close()
	}
}

// TestVerifySCT exercises an immediate verification via an inclusion proof as
// well as a delayed SCT verification where the SCT is stored for later verification.
func TestVerifySCT(t *testing.T) {
	l, err := NewLogVerifier([]byte(pem), "")
	if err != nil {
		t.Fatalf("NewLogVerifier(): %v", err)
	}
	for _, tc := range []struct {
		smh, sct, sth, inclusion, hash, consistency string
		cachedSCTs                                  int
	}{
		// STH 0, UpdateSTH, Verify SCT + MMD < new STH.
		{
			`{ "map_head": { "epoch": 1, "root": "vCRFZf+KdYcOBuD4bFtDMnqKfWO1io5d8bI1Gh6dSWs=", "issue_time": { "seconds": 2 } }, "signatures": { "6efc5bec": { "hash_algorithm": 4, "sig_algorithm": 3, "signature": "MEQCIHgCT+BF3DFZkBXNZDL4wBOhuBkFybJEifdszVYvMMZQAiBEZRLKrj6g9+6TN32OJfECjkc4CZITQLUYlkdRm+0wmw==" } } }`,
			`{ "sct_version": 0, "id": "3xwuwRUAlFJHqWFoMl3cXHlZ6PfG04j8AC4LvT9012Q=", "timestamp": 1469818883686, "extensions": "", "signature": "BAMARjBEAiBRH\/bZrc4Fl6B6pTWsj0vo9elzbWzgpDKpczEod4pRDwIga03DUchNDRWwtv2xHi7v9kzestFGkEpyMn1jYTsk9nc=" }`,
			`{ "tree_size": 29, "timestamp": 1470441152103, "sha256_root_hash": "KtOs5kyiH2mf4xSuREERqIbC4wsuwm6e7EXqXKc\/FLM=", "tree_head_signature": "BAMARzBFAiEAvgi7ETkLQTwCXR1rePmyj2CxDLnGIcS5kOoH770btzICIAw5yjO8oYR+yf\/QK4Ks59YOnkQA+I1OywGPrZIvPuU0" }`,
			`{ "leaf_index": 26, "audit_path": [ "z6OXtl3FHCwSIDfNAwj\/5HY\/vXMgN5u3Y2LlfWmrHgY=", "grgSU6rjELf4Dff+LJ\/AjdgFt2SW85KW+Qfx3i9LSRk=", "MxibgM+03nha\/k4sbUrUgvgQ50lCYHDH6f8IzTCNYgE=", "BYB0BDK4jX6UPmSboGtIUMe9SwqLaJe6X0BkSWXCGOc=", "t9rD1TCqf2B1s8z15+fPmkRe1JVvjf2VNPhRzt\/m8nM=" ] }`,
			"t0A8H7hDbMSFIYZSaez/JxZhhuCySpUvz4iw6RpECO0=",
			"",
			0,
		},
		// Recent SCT that must be cached.
		{
			`{ "map_head": { "epoch": 88, "root": "vCRFZf+KdYcOBuD4bFtDMnqKfWO1io5d8bI1Gh6dSWs=", "issue_time": { "seconds": 2 } }, "signatures": { "6efc5bec": { "hash_algorithm": 4, "sig_algorithm": 3, "signature": "MEQCIHgCT+BF3DFZkBXNZDL4wBOhuBkFybJEifdszVYvMMZQAiBEZRLKrj6g9+6TN32OJfECjkc4CZITQLUYlkdRm+0wmw==" } } }`,
			`{ "sct_version": 0, "id": "3xwuwRUAlFJHqWFoMl3cXHlZ6PfG04j8AC4LvT9012Q=", "timestamp": 1470446585056, "extensions": "", "signature": "BAMARzBFAiEAmeslS3299VTS+Yx1Ie+kyL5XdVaAeK45qmpvXdMJb0MCIGDWkRCJcQTY2Ps0VOIUV4CRWFPN2XiCNUJcu2CtbK7P" }`,
			`{ "tree_size": 31, "timestamp": 1470443243216, "sha256_root_hash": "ViC4zIwf+JBLBJFPZh2wJL9dhLxqcA5QcT0irqDvrJI=", "tree_head_signature": "BAMASDBGAiEAxjtFdJ\/M+o1qQuxG5m9U0YTkV53OVXaL3n4bh05gCQACIQDu1UyM4r9EMTE\/s9PA1NdUYcd+u4KJjbxONnKh9AYKZw==" }`,
			"", "",
			`{ "consistency": [ "MxibgM+03nha\/k4sbUrUgvgQ50lCYHDH6f8IzTCNYgE=", "96glM98fKO+i8PMDB9a7BLUVOq0lLUhLuSkENOmZEaw=", "DKW8LAKFwYHwvAloKsIi8ag12d9Hd5k+sSZZytE97gM=", "YM1Cfw914h1lj7MR\/JMS+Hm\/Eqn4N79JsfMUnFrhaEo=", "BYB0BDK4jX6UPmSboGtIUMe9SwqLaJe6X0BkSWXCGOc=", "t9rD1TCqf2B1s8z15+fPmkRe1JVvjf2VNPhRzt\/m8nM=" ] }`,
			1,
		},
	} {
		hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/ct/v1/get-sth":
				w.Write([]byte(tc.sth))
			case "/ct/v1/get-sth-consistency":
				w.Write([]byte(tc.consistency))
			case "/ct/v1/add-json":
				w.Write([]byte(tc.sct))
			case "/ct/v1/get-proof-by-hash":
				if err := r.ParseForm(); err != nil {
					t.Fatalf("Failed to parse form: %v", err)
				}
				if got, want := r.Form["hash"][0], tc.hash; got != want {
					t.Errorf("Incorrect request hash:\n%v, wanted\n%v", got, want)
				}
				w.Write([]byte(tc.inclusion))
			default:
				t.Errorf("Incorrect URL path: %s", r.URL.Path)
			}
		}))
		l.ctlog = logclient.New(hs.URL, nil)
		var smh ctmap.SignedMapHead
		if err := json.Unmarshal([]byte(tc.smh), &smh); err != nil {
			t.Errorf("Error decoding SMH: %v", err)
		}
		sct, err := l.ctlog.AddJSON(&smh)
		if err != nil {
			t.Errorf("Failed to get SCT from AddJSON: %v", err)
		}
		if err := l.VerifySCT(&smh, sct); err != nil {
			t.Errorf("VerifySCT(): %v", err)
		}
		if got := len(l.scts); got != tc.cachedSCTs {
			t.Errorf("len(scts): %v, want %v", got, tc.cachedSCTs)
		}
		hs.Close()
	}
}

func TestVerifySCTSig(t *testing.T) {
	hs := NewCTServer(t)
	defer hs.Close()
	l, err := NewLogVerifier([]byte(pem), hs.URL)
	if err != nil {
		t.Fatalf("NewLogVerifier(): %v", err)
	}

	var smh ctmap.SignedMapHead
	if err := json.Unmarshal([]byte(addJSONReq), &smh); err != nil {
		t.Fatalf("Error decoding SMH: %v", err)
	}
	sct, err := l.ctlog.AddJSON(&smh)
	if err != nil {
		t.Fatalf("Failed to get SCT from AddJSON: %v", err)
	}
	e := ct.LogEntry{Leaf: *ct.CreateJSONMerkleTreeLeaf(smh, sct.Timestamp)}
	if err := l.ver.VerifySCTSignature(*sct, e); err != nil {
		t.Fatalf("verifySCTSig(): %v", err)
	}
}

// TestVerifySavedSCTs ensures that cached SCTs are verified.
func TestVerifySavedSCTs(t *testing.T) {
	l, err := NewLogVerifier([]byte(pem), "")
	if err != nil {
		t.Fatalf("NewLogVerifier(): %v", err)
	}
	for i, tc := range []struct {
		smh, sct, sth, inclusion, hash string
	}{
		// STH 0, UpdateSTH, Verify SCT + MMD < new STH.
		{
			`{ "map_head": { "epoch": 1, "root": "vCRFZf+KdYcOBuD4bFtDMnqKfWO1io5d8bI1Gh6dSWs=", "issue_time": { "seconds": 2 } }, "signatures": { "6efc5bec": { "hash_algorithm": 4, "sig_algorithm": 3, "signature": "MEQCIHgCT+BF3DFZkBXNZDL4wBOhuBkFybJEifdszVYvMMZQAiBEZRLKrj6g9+6TN32OJfECjkc4CZITQLUYlkdRm+0wmw==" } } }`,
			`{ "sct_version": 0, "id": "3xwuwRUAlFJHqWFoMl3cXHlZ6PfG04j8AC4LvT9012Q=", "timestamp": 1469818883686, "extensions": "", "signature": "BAMARjBEAiBRH\/bZrc4Fl6B6pTWsj0vo9elzbWzgpDKpczEod4pRDwIga03DUchNDRWwtv2xHi7v9kzestFGkEpyMn1jYTsk9nc=" }`,
			`{ "tree_size": 29, "timestamp": 1470441152103, "sha256_root_hash": "KtOs5kyiH2mf4xSuREERqIbC4wsuwm6e7EXqXKc\/FLM=", "tree_head_signature": "BAMARzBFAiEAvgi7ETkLQTwCXR1rePmyj2CxDLnGIcS5kOoH770btzICIAw5yjO8oYR+yf\/QK4Ks59YOnkQA+I1OywGPrZIvPuU0" }`,
			`{ "leaf_index": 26, "audit_path": [ "z6OXtl3FHCwSIDfNAwj\/5HY\/vXMgN5u3Y2LlfWmrHgY=", "grgSU6rjELf4Dff+LJ\/AjdgFt2SW85KW+Qfx3i9LSRk=", "MxibgM+03nha\/k4sbUrUgvgQ50lCYHDH6f8IzTCNYgE=", "BYB0BDK4jX6UPmSboGtIUMe9SwqLaJe6X0BkSWXCGOc=", "t9rD1TCqf2B1s8z15+fPmkRe1JVvjf2VNPhRzt\/m8nM=" ] }`,
			"t0A8H7hDbMSFIYZSaez/JxZhhuCySpUvz4iw6RpECO0=",
		},
	} {
		hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/ct/v1/get-sth":
				w.Write([]byte(tc.sth))
			case "/ct/v1/add-json":
				w.Write([]byte(tc.sct))
			case "/ct/v1/get-proof-by-hash":
				if err := r.ParseForm(); err != nil {
					t.Fatalf("Failed to parse form: %v", err)
				}
				if got, want := r.Form["hash"][0], tc.hash; got != want {
					t.Errorf("Incorrect request hash:\n%v, wanted\n%v", got, want)
				}
				w.Write([]byte(tc.inclusion))
			default:
				t.Errorf("Incorrect URL path: %s", r.URL.Path)
			}
		}))
		l.ctlog = logclient.New(hs.URL, nil)
		var smh ctmap.SignedMapHead
		if err := json.Unmarshal([]byte(tc.smh), &smh); err != nil {
			t.Errorf("Error decoding SMH: %v", err)
		}
		sct, err := l.ctlog.AddJSON(&smh)
		if err != nil {
			t.Errorf("Failed to get SCT from AddJSON: %v", err)
		}
		// Manually set Cache entry.
		l.scts[sct] = SCTEntry{sct, &smh}
		if entries := l.VerifySavedSCTs(); len(entries) != 0 {
			t.Errorf("%v: VerifySavedSCTs(): %v", i, entries)
		}
		hs.Close()
	}
}
