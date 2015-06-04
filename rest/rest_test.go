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

package rest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	context "golang.org/x/net/context"
)

type FakeServer struct {
}

func Fake_Handler(srv interface{}, ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	w.Write([]byte("hi"))
	return nil
}

func TestFoo(t *testing.T) {
	v1 := &FakeServer{}
	s := New(v1)
	s.AddHandler("/hi", "GET", Fake_Handler)

	server := httptest.NewServer(s.Handlers())
	defer server.Close()
	res, err := http.Get(fmt.Sprintf("%s/hi", server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := res.StatusCode, http.StatusOK; got != want {
		t.Errorf("GET: %v = %v, want %v", res.Request.URL, got, want)
	}
}
