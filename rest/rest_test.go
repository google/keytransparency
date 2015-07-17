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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/e2e-key-server/rest/handlers"

	v2pb "github.com/google/e2e-key-server/proto/v2"
	context "golang.org/x/net/context"
)

const (
	valid_ts   = "2015-05-18T23:58:36.000Z"
	invalid_ts = "Mon May 18 23:58:36 UTC 2015"
	ts_seconds = 1431993516
)

type fakeJSONParserReader struct {
	*bytes.Buffer
}

func (pr fakeJSONParserReader) Close() error {
	return nil
}

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
	var tests = []struct {
		userId       string
		appId        string
		tm           string
		isOutTimeNil bool
		outSeconds   int64
		outNanos     int
		parserNilErr bool
	}{
		{"e2eshare.test@gmail.com", "gmail", valid_ts, false, ts_seconds, 0, true},
		{"e2eshare.test@gmail.com", "", valid_ts, false, ts_seconds, 0, true},
		{"e2eshare.test@gmail.com", "gmail", "", true, 0, 0, true},
		{"e2eshare.test@gmail.com", "", "", true, 0, 0, true},
		{"e2eshare.test@gmail.com", "gmail", invalid_ts, false, time.Now().Unix(), 0, false},
	}

	for _, test := range tests {
		path := "/v1/users/" + test.userId
		if test.appId != "" && test.tm != "" {
			path += "?app_id=" + test.appId + "&time=" + test.tm
		} else if test.appId == "" && test.tm != "" {
			path += "?time=" + test.tm
		} else if test.appId != "" && test.tm == "" {
			path += "?app_id=" + test.appId
		}
		rInfo := handlers.RouteInfo{
			path,
			2,
			-1,
			"GET",
			Fake_Initializer,
			Fake_RequestHandler,
		}
		// Body is empty when invoking get user API
		jsonBody := ""

		info := GetUser_InitializeHandlerInfo(rInfo)

		switch info.Arg.(type) {
		case *v2pb.GetUserRequest:
			break
		default:
			t.Errorf("info.Arg is not of type v2pb.GetUserRequest")
		}

		r, _ := http.NewRequest(rInfo.Method, rInfo.Path, fakeJSONParserReader{bytes.NewBufferString(jsonBody)})
		err := info.Parser(r, &info.Arg)
		if test.parserNilErr != (err == nil) {
			t.Errorf("Unexpected err = (%v), want nil = %v", err, test.parserNilErr)
		}
		// If there's an error parsing, the test cannot be
		// completed. The parsing error might be expected though
		if err != nil {
			continue
		}

		// Call JSONDecoder to simulate decoding JSON -> Proto
		err = JSONDecoder(r, &info.Arg)
		if err == nil {
			t.Errorf("Error while calling JSONDecoder, this should not happen.")
		}

		if got, want := info.Arg.(*v2pb.GetUserRequest).UserId, test.userId; got != want {
			t.Errorf("UserId = %v, want %v", got, want)
		}
		if got, want := info.Arg.(*v2pb.GetUserRequest).AppId, test.appId; got != want {
			t.Errorf("AppId = %v, want %v", got, want)
		}
		if test.isOutTimeNil == false {
			if gots, gotn, wants, wantn := info.Arg.(*v2pb.GetUserRequest).Time.Seconds, info.Arg.(*v2pb.GetUserRequest).Time.Nanos, test.outSeconds, test.outNanos; gots != wants || gotn != int32(wantn) {
				t.Errorf("Time = %v [sec] %v [nsec], want %v [sec] %v [nsec]", gots, gotn, wants, wantn)
			}
		} else {
			if info.Arg.(*v2pb.GetUserRequest).Time != nil {
				t.Errorf("Time must be nil and it's not")
			}
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
}

func TestCreateKey_InitiateHandlerInfo(t *testing.T) {
	var tests = []struct {
		userId         string
		userIdIndex    int
		tm             string
		isTimeNil      bool
		outSeconds     int64
		outNanos       int
		jsonBody       string
		parserNilErr   bool
		verifierNilErr bool
	}{
		{"e2eshare.test@gmail.com", 2,
			valid_ts, false, ts_seconds, 0,
			"{\"signed_key\":{\"key\": {\"creation_time\": \"" + valid_ts + "\"}}}",
			true, true},
		{"e2eshare.test@gmail.com", 4,
			valid_ts, false, ts_seconds, 0,
			"{\"signed_key\":{\"key\": {\"creation_time\": \"" + valid_ts + "\"}}}",
			false, true},
		{"e2eshare.test@gmail.com", -1,
			valid_ts, false, ts_seconds, 0,
			"{\"signed_key\":{\"key\": {\"creation_time\": \"" + valid_ts + "\"}}}",
			false, true},
		{"e2eshare.test@gmail.com", 2,
			valid_ts, true, 0, 0,
			"{\"signed_key\":{\"key\": {\"creation_time\": \"\"}}}",
			false, false},
		{"e2eshare.test@gmail.com", 2,
			valid_ts, true, 0, 0,
			"{}",
			true, false},
	}
	for _, test := range tests {
		path := "/v1/users/" + test.userId + "/keys"
		rInfo := handlers.RouteInfo{
			path,
			test.userIdIndex,
			-1,
			"POST",
			Fake_Initializer,
			Fake_RequestHandler,
		}

		info := CreateKey_InitializeHandlerInfo(rInfo)

		switch info.Arg.(type) {
		case *v2pb.CreateKeyRequest:
			break
		default:
			t.Errorf("info.Arg is not of type v2pb.CreateKeyRequest")
		}

		r, _ := http.NewRequest(rInfo.Method, rInfo.Path, fakeJSONParserReader{bytes.NewBufferString(test.jsonBody)})
		err := info.Parser(r, &info.Arg)
		if test.parserNilErr != (err == nil) {
			t.Errorf("Unexpected err = (%v), want nil = %v", err, test.parserNilErr)
		}
		// If there's an error parsing, the test cannot be
		// completed. The parsing error might be expected though
		if err != nil {
			continue
		}

		// Call JSONDecoder to simulate decoding JSON -> Proto
		err = JSONDecoder(r, &info.Arg)
		if err != nil {
			t.Errorf("Error while calling JSONDecoder, this should not happen. err: %v", err)
		}

		// Verify that all required fields exist
		err = info.Verifier(info.Arg)
		if test.verifierNilErr != (err == nil) {
			t.Errorf("Unexpected err = (%v), want nil = %v", err, test.parserNilErr)
		}
		// If there's an error verifying, the test cannot be
		// completed. The verifying error might be expected though
		if err != nil {
			continue
		}

		if got, want := info.Arg.(*v2pb.CreateKeyRequest).UserId, test.userId; got != want {
			t.Errorf("UserId = %v, want %v", got, want)
		}
		if test.isTimeNil == false {
			if gots, gotn, wants, wantn := info.Arg.(*v2pb.CreateKeyRequest).SignedKey.Key.CreationTime.Seconds, info.Arg.(*v2pb.CreateKeyRequest).SignedKey.Key.CreationTime.Nanos, test.outSeconds, test.outNanos; gots != wants || gotn != int32(wantn) {
				t.Errorf("Time = %v [sec] %v [nsec], want %v [sec] %v [nsec]", gots, gotn, wants, wantn)
			}
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
}

func TestUpdateKey_InitiateHandlerInfo(t *testing.T) {
	var tests = []struct {
		userId         string
		userIdIndex    int
		keyId          string
		keyIdIndex     int
		tm             string
		isTimeNil      bool
		outSeconds     int64
		outNanos       int
		jsonBody       string
		parserNilErr   bool
		verifierNilErr bool
	}{
		{"e2eshare.test@gmail.com", 2, "mykey", 4,
			valid_ts, false, ts_seconds, 0,
			"{\"signed_key\":{\"key\": {\"creation_time\": \"" + valid_ts + "\"}}}",
			true, true},
		{"e2eshare.test@gmail.com", 2, "mykey", 5,
			valid_ts, false, ts_seconds, 0,
			"{\"signed_key\":{\"key\": {\"creation_time\": \"" + valid_ts + "\"}}}",
			false, true},
		{"e2eshare.test@gmail.com", 2, "mykey", -1,
			valid_ts, false, ts_seconds, 0,
			"{\"signed_key\":{\"key\": {\"creation_time\": \"" + valid_ts + "\"}}}",
			false, true},
		{"e2eshare.test@gmail.com", 2, "mykey", 4,
			valid_ts, true, 0, 0,
			"{\"signed_key\":{\"key\": {\"creation_time\": \"\"}}}",
			false, false},
		{"e2eshare.test@gmail.com", 2, "mykey", 4,
			valid_ts, true, 0, 0,
			"{}",
			true, false},
	}
	for _, test := range tests {
		path := "/v1/users/" + test.userId + "/keys/" + test.keyId
		rInfo := handlers.RouteInfo{
			path,
			test.userIdIndex,
			test.keyIdIndex,
			"POST",
			Fake_Initializer,
			Fake_RequestHandler,
		}

		info := UpdateKey_InitializeHandlerInfo(rInfo)

		switch info.Arg.(type) {
		case *v2pb.UpdateKeyRequest:
			break
		default:
			t.Errorf("info.Arg is not of type v2pb.UpdateKeyRequest")
		}

		r, _ := http.NewRequest(rInfo.Method, rInfo.Path, fakeJSONParserReader{bytes.NewBufferString(test.jsonBody)})
		err := info.Parser(r, &info.Arg)
		if test.parserNilErr != (err == nil) {
			t.Errorf("Unexpected err = (%v), want nil = %v", err, test.parserNilErr)
		}
		// If there's an error parsing, the test cannot be
		// completed. The parsing error might be expected though
		if err != nil {
			continue
		}

		// Call JSONDecoder to simulate decoding JSON -> Proto
		err = JSONDecoder(r, &info.Arg)
		if err != nil {
			t.Errorf("Error while calling JSONDecoder, this should not happen. err: %v", err)
		}

		// Verify that all required fields exist
		err = info.Verifier(info.Arg)
		if test.verifierNilErr != (err == nil) {
			t.Errorf("Unexpected err = (%v), want nil = %v", err, test.parserNilErr)
		}
		// If there's an error verifying, the test cannot be
		// completed. The verifying error might be expected though
		if err != nil {
			continue
		}

		if got, want := info.Arg.(*v2pb.UpdateKeyRequest).UserId, test.userId; got != want {
			t.Errorf("UserId = %v, want %v", got, want)
		}
		if got, want := info.Arg.(*v2pb.UpdateKeyRequest).KeyId, test.keyId; got != want {
			t.Errorf("KeyId = %v, want %v", got, want)
		}
		if test.isTimeNil == false {
			if gots, gotn, wants, wantn := info.Arg.(*v2pb.UpdateKeyRequest).SignedKey.Key.CreationTime.Seconds, info.Arg.(*v2pb.UpdateKeyRequest).SignedKey.Key.CreationTime.Nanos, test.outSeconds, test.outNanos; gots != wants || gotn != int32(wantn) {
				t.Errorf("Time = %v [sec] %v [nsec], want %v [sec] %v [nsec]", gots, gotn, wants, wantn)
			}
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
}

func JSONDecoder(r *http.Request, v interface{}) error {
	decoder := json.NewDecoder(r.Body)
	return decoder.Decode(v)
}

func TestParseURLComponent(t *testing.T) {
	var tests = []struct {
		comp   []string
		index  int
		out    string
		nilErr bool
	}{
		{[]string{"v1", "users", "e2eshare.test@gmail.com"}, 2, "e2eshare.test@gmail.com", true},
		{[]string{"v1", "users", "e2eshare.test@cs.ox.ac.uk"}, -1, "", false},
		{[]string{"v1", "users", "e2eshare.test@cs.ox.ac.uk"}, 3, "", false},
	}
	for _, test := range tests {
		gots, gote := parseURLComponent(test.comp, test.index)
		wants := test.out
		wante := test.nilErr
		if gots != wants || wante != (gote == nil) {
			t.Errorf("Error while parsing User ID. Input = (%v, %v), got ('%v', %v), want ('%v', nil = %v)", test.comp, test.index, gots, gote, wants, wante)
		}
	}
}

func TestParseJson(t *testing.T) {
	var tests = []struct {
		inJSON    string
		outJSON   string
		outNilErr bool
	}{
		// Basic cases
		{"\"creation_time\": \"" + valid_ts + "\"",
			"\"creation_time\": {\"seconds\": " +
				strconv.Itoa(ts_seconds) + ", \"nanos\": 0}", true},
		{"{\"creation_time\": \"" + valid_ts + "\"}",
			"{\"creation_time\": {\"seconds\": " +
				strconv.Itoa(ts_seconds) + ", \"nanos\": 0}}", true},
		// Nested case
		{"{\"signed_key\":{\"key\": {\"creation_time\": \"" + valid_ts + "\"}}}",
			"{\"signed_key\":{\"key\": {\"creation_time\": {\"seconds\": " +
				strconv.Itoa(ts_seconds) + ", \"nanos\": 0}}}}", true},
		// Nothing to be changed
		{"nothing to be changed here", "nothing to be changed here", true},
		// Multiple keywords
		{"\"creation_time\": \"" + valid_ts + "\", \"creation_time\": \"" +
			valid_ts + "\"",
			"\"creation_time\": {\"seconds\": " + strconv.Itoa(ts_seconds) +
				", \"nanos\": 0}, \"creation_time\": {\"seconds\": " +
				strconv.Itoa(ts_seconds) + ", \"nanos\": 0}", true},
		// Invalid timestamp
		{"\"creation_time\": \"invalid\"", "\"creation_time\": \"invalid\"", false},
		// Malformed JSON, missing " at the beginning of invalid timestamp
		{"\"creation_time\": invalid\"", "\"creation_time\": invalid\"", true},
		// Malformed JSON, missing " at the end of invalid timestamp
		{"\"creation_time\": \"invalid", "\"creation_time\": \"invalid", true},
		// Malformed JSON, missing " at the beginning and end of invalid timestamp
		{"\"creation_time\": invalid", "\"creation_time\": invalid", true},
		// Malformed JSON, missing " at the end of valid timestamp
		{"\"creation_time\": \"" + valid_ts, "\"creation_time\": \"" + valid_ts, true},
		// keyword is not surrounded by "", in four cases:
		//     invalid timestamp, basic, nested and multiple keywords
		{"creation_time: \"invalid\"", "creation_time: \"invalid\"", false},
		{"{creation_time: \"" + valid_ts + "\"}",
			"{creation_time: {\"seconds\": " +
				strconv.Itoa(ts_seconds) + ", \"nanos\": 0}}", true},
		{"{\"signed_key\":{\"key\": {creation_time: \"" + valid_ts + "\"}}}",
			"{\"signed_key\":{\"key\": {creation_time: {\"seconds\": " +
				strconv.Itoa(ts_seconds) + ", \"nanos\": 0}}}}", true},
		// Only first keyword is not surrounded by ""
		{"creation_time: \"" + valid_ts + "\", \"creation_time\": \"" +
			valid_ts + "\"",
			"creation_time: {\"seconds\": " + strconv.Itoa(ts_seconds) +
				", \"nanos\": 0}, \"creation_time\": {\"seconds\": " +
				strconv.Itoa(ts_seconds) + ", \"nanos\": 0}", true},
		// Timestamp is not surrounded by "" and there's another key:value after
		{"{\"signed_key\":{\"key\": {\"creation_time\": " + valid_ts +
			", app_id: \"gmail\"}}}",
			"{\"signed_key\":{\"key\": {\"creation_time\": " + valid_ts +
				", app_id: \"gmail\"}}}", false},
	}

	for _, test := range tests {
		r, _ := http.NewRequest("", "", fakeJSONParserReader{bytes.NewBufferString(test.inJSON)})
		err := parseJSON(r, "creation_time")
		if test.outNilErr != (err == nil) {
			t.Errorf("Unexpected err = (%v), want nil = %v", err, test.outNilErr)
		}
		buf := new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		if got, want := buf.String(), test.outJSON; got != want {
			t.Errorf("Out JSON = (%v), want (%v)", got, want)
		}
	}
}
