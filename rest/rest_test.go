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
	"net/url"
	"testing"
	"time"

	"github.com/google/e2e-key-server/rest/handlers"

	v2pb "github.com/google/e2e-key-server/proto/v2"
	context "golang.org/x/net/context"
)

type FakeServer struct {
}

func Fake_Handler(srv interface{}, ctx context.Context, w http.ResponseWriter, r *http.Request, info *handlers.HandlerInfo) error {
	w.Write([]byte("hi"))
	return nil
}

func Fake_Initializer(rInfo handlers.RouteInfo) *handlers.HandlerInfo {
	return nil
}

func Fake_RequestHandler(srv interface{}, ctx context.Context, arg interface{}) (*interface{}, error) {
	b := true
	i := new(interface{})
	*i = b
	return i, nil
}

func TestFoo(t *testing.T) {
	v1 := &FakeServer{}
	s := New(v1)
	rInfo := handlers.RouteInfo{
		"/hi",
		-1,
		"GET",
		Fake_Initializer,
		Fake_RequestHandler,
	}
	s.AddHandler(rInfo, Fake_Handler)

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

func TestGetUser_InitiateHandlerInfo(t *testing.T) {
	email := "e2eshare.test@gmail.com"
	appId := "gmail"
	tm := time.Now().Format(time.RFC3339)
	path := "/v1/users/" + email + "?appId=" + appId + "&time=" + tm

	rInfo := handlers.RouteInfo{
		path,
		2,
		"GET",
		Fake_Initializer,
		Fake_RequestHandler,
	}
	info := GetUser_InitializeHandlerInfo(rInfo)

	switch info.Arg.(type) {
	case *v2pb.GetUserRequest:
		break
	default:
		t.Errorf("info.Arg is not of type v2pb.GetUserRequest")
	}

	u, err := url.Parse(path)
	if err != nil {
		t.Fatal(err)
	}

	err = info.Parser(u, &info.Arg)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Arg.(*v2pb.GetUserRequest).UserId, email; got != want {
		t.Errorf("UserId = %v, want %v", got, want)
	}
	if got, want := info.Arg.(*v2pb.GetUserRequest).AppId, appId; got != want {
		t.Errorf("AppId = %v, want %v", got, want)
	}
	tt, _ := time.Parse(time.RFC3339, tm)
	if gots, gotn, wants, wantn := info.Arg.(*v2pb.GetUserRequest).Time.Seconds, info.Arg.(*v2pb.GetUserRequest).Time.Nanos, tt.Unix(), tt.Nanosecond(); gots != wants || gotn != int32(wantn) {
		t.Errorf("Time = %v [sec] %v [nsec], want %v [sec] %v [nsec]", gots, gotn, wants, wantn)
	}

	v1 := &FakeServer{}
	srv := New(v1)
	resp, err := info.H(srv, nil, nil)
	if err != nil {
		t.Errorf("Error while calling Fake_RequestHandler, this should not happen.")
	}
	if got, want := (*resp).(bool), true; got != want {
		t.Errorf("resp = %v, want %v.", got, want)
	}
}
