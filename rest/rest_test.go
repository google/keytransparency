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

package rest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/google/e2e-key-server/rest/handlers"
	"github.com/gorilla/mux"

	pb "github.com/google/e2e-key-server/proto/security_e2ekeys"
	v1pb "github.com/google/e2e-key-server/proto/security_e2ekeys_v1"
	context "golang.org/x/net/context"
)

const (
	validTs                        = "2016-05-18T23:58:36.000Z"
	invalidTs                      = "Mon May 18 23:58:36 UTC 2016"
	tsSeconds                      = 1463615916
	primaryTestEpoch               = "2367"
	primaryTestPageSize            = "653"
	primaryTestCommitmentTimestamp = "8626"
	primaryUserEmail               = "e2eshare.test@gmail.com"
	primaryTestAppId               = "gmail"
	testRealm                      = "google.com"
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

func TestServer(t *testing.T) {
	v1 := &FakeServer{}
	s := New(v1, testRealm)
	rInfo := handlers.RouteInfo{
		"/hi",
		"GET",
		Fake_Initializer,
		Fake_RequestHandler,
	}
	s.AddHandler(rInfo, Fake_Handler, v1)

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

func TestGetEntryV1_InitiateHandlerInfo(t *testing.T) {
	mx := mux.NewRouter()
	mx.KeepContext = true
	mx.HandleFunc(fmt.Sprintf("/v1/users/{%v}", handlers.UserIdKeyword), Fake_HTTPHandler)

	i, _ := strconv.ParseInt(primaryTestEpoch, 10, 64)
	var tests = []struct {
		path         string
		userId       string
		appId        string
		epoch        int64
		parserNilErr bool
	}{
		{fmt.Sprintf("/v1/users/%v?app_id=%v&epoch=%v", primaryUserEmail, primaryTestAppId, primaryTestEpoch), primaryUserEmail, primaryTestAppId, i, true},
		{"/v1/users/" + primaryUserEmail + "?epoch=" + primaryTestEpoch, primaryUserEmail, "", i, true},
		{"/v1/users/" + primaryUserEmail + "?app_id=" + primaryTestAppId, primaryUserEmail, primaryTestAppId, 0, true},
		{"/v1/users/" + primaryUserEmail, primaryUserEmail, "", 0, true},
		{"/v1/users/" + primaryUserEmail + "?epoch=-2587", primaryUserEmail, "", 0, false}, // Invalid epoch format.
		{"/v1/users/" + primaryUserEmail + "?epoch=greatepoch", primaryUserEmail, "", 0, false},
	}

	for i, test := range tests {
		rInfo := handlers.RouteInfo{
			test.path,
			"GET",
			Fake_Initializer,
			Fake_RequestHandler,
		}
		// Body is empty when invoking get user API.
		jsonBody := "{}"

		info := GetEntryV1_InitializeHandlerInfo(rInfo)

		if _, ok := info.Arg.(*pb.GetEntryRequest); !ok {
			t.Errorf("Test[%v]: info.Arg is not of type pb.GetEntryRequest", i)
		}

		r, _ := http.NewRequest(rInfo.Method, rInfo.Path, fakeJSONParserReader{bytes.NewBufferString(jsonBody)})
		mx.ServeHTTP(nil, r)
		err := info.Parser(r, &info.Arg)
		if got, want := (err == nil), test.parserNilErr; got != want {
			t.Errorf("Test[%v]: Unexpected parser err = (%v), want nil = %v", i, err, test.parserNilErr)
		}
		// If there's an error parsing, the test cannot be completed.
		// The parsing error might be expected though.
		if err != nil {
			continue
		}

		// Call JSONDecoder to simulate decoding JSON -> Proto.
		err = JSONDecoder(r, &info.Arg)
		if err != nil {
			t.Errorf("Test[%v]: Error while calling JSONDecoder, this should not happen. err: %v", i, err)
		}

		if got, want := info.Arg.(*pb.GetEntryRequest).UserId, test.userId; got != want {
			t.Errorf("Test[%v]: UserId = %v, want %v", i, got, want)
		}
		if got, want := info.Arg.(*pb.GetEntryRequest).EpochEnd, test.epoch; got != want {
			t.Errorf("Test[%v]: Epoch = %v, want %v", i, got, want)
		}

		v1 := &FakeServer{}
		srv := New(v1, testRealm)
		resp, err := info.H(srv, nil, nil)
		if err != nil {
			t.Errorf("Test[%v]: Error while calling Fake_RequestHandler, this should not happen.", i)
		}
		if got, want := (*resp).(bool), true; got != want {
			t.Errorf("Test[%v]: resp = %v, want %v.", i, got, want)
		}
	}
}

func TestHkpLookup_InitiateHandlerInfo(t *testing.T) {
	mx := mux.NewRouter()
	mx.KeepContext = true
	mx.HandleFunc("/v1/hkp/lookup", Fake_HTTPHandler)

	var tests = []struct {
		path         string
		op           string
		search       string
		options      string
		parserNilErr bool
	}{
		{"/v1/hkp/lookup?op=get&search=" + url.QueryEscape(primaryUserEmail) + "&options=mr", "get", primaryUserEmail, "mr", true}, // This should pass.
		{"/v1/hkp/lookup?op=get&search=" + primaryUserEmail + "&options=mr", "get", primaryUserEmail, "mr", true},                  // Unescaped query string.
		{"/v1/hkp/lookup?search=" + url.QueryEscape(primaryUserEmail) + "&options=mr", "", primaryUserEmail, "mr", true},           // Missing op.
		{"/v1/hkp/lookup?op=get&options=mr", "get", "", "mr", true},                                                                // Missing search.
		{"/v1/hkp/lookup?op=get&search=" + url.QueryEscape(primaryUserEmail), "get", primaryUserEmail, "", true},                   // Missing options.
		{"/v1/hkp/lookup?options=mr", "", "", "mr", true},                                                                          // Missing op and search.
		{"/v1/hkp/lookup?search=" + url.QueryEscape(primaryUserEmail), "", primaryUserEmail, "", true},                             // Missing op and options.
		{"/v1/hkp/lookup?op=get", "get", "", "", true},                                                                             // Missing search and options.
		{"/v1/hkp/lookup", "", "", "", true},                                                                                       // Missing op, search and options.
	}

	for i, test := range tests {
		rInfo := handlers.RouteInfo{
			test.path,
			"GET",
			Fake_Initializer,
			Fake_RequestHandler,
		}
		// Body is empty when invoking HKP lookup API.
		jsonBody := "{}"

		info := HkpLookup_InitializeHandlerInfo(rInfo)

		if _, ok := info.Arg.(*v1pb.HkpLookupRequest); !ok {
			t.Errorf("Test[%v]: info.Arg is not of type v1pb.HkpLookupRequest", i)
		}

		r, _ := http.NewRequest(rInfo.Method, rInfo.Path, fakeJSONParserReader{bytes.NewBufferString(jsonBody)})
		mx.ServeHTTP(nil, r)
		err := info.Parser(r, &info.Arg)
		if got, want := (err == nil), test.parserNilErr; got != want {
			t.Errorf("Test[%v]: Unexpected parser err = (%v), want nil = %v", i, err, test.parserNilErr)
		}
		// If there's an error parsing, the test cannot be completed.
		// The parsing error might be expected though.
		if err != nil {
			continue
		}

		if got, want := info.Arg.(*v1pb.HkpLookupRequest).Op, test.op; got != want {
			t.Errorf("Test[%v]: Op = %v, want %v", i, got, want)
		}
		if got, want := info.Arg.(*v1pb.HkpLookupRequest).Search, test.search; got != want {
			t.Errorf("Test[%v]: Search = %v, want %v", i, got, want)
		}
		if got, want := info.Arg.(*v1pb.HkpLookupRequest).Options, test.options; got != want {
			t.Errorf("Test[%v]: Options = %v, want %v", i, got, want)
		}

		v1 := &FakeServer{}
		srv := New(v1, testRealm)
		resp, err := info.H(srv, nil, nil)
		if err != nil {
			t.Errorf("Test[%v]: Error while calling Fake_RequestHandler, this should not happen.", i)
		}
		if got, want := (*resp).(bool), true; got != want {
			t.Errorf("Test[%v]: resp = %v, want %v.", i, got, want)
		}
	}
}

func TestGetEntryV2_InitiateHandlerInfo(t *testing.T) {
	mx := mux.NewRouter()
	mx.KeepContext = true
	mx.HandleFunc("/v2/users/{"+handlers.UserIdKeyword+"}", Fake_HTTPHandler)

	i, _ := strconv.ParseInt(primaryTestEpoch, 10, 64)
	var tests = []struct {
		path         string
		userId       string
		appId        string
		epoch        int64
		parserNilErr bool
	}{
		{"/v2/users/" + primaryUserEmail + "?app_id=" + primaryTestAppId + "&epoch=" + primaryTestEpoch, primaryUserEmail, primaryTestAppId, i, true},
		{"/v2/users/" + primaryUserEmail + "?epoch=" + primaryTestEpoch, primaryUserEmail, "", i, true},
		{"/v2/users/" + primaryUserEmail + "?app_id=" + primaryTestAppId, primaryUserEmail, primaryTestAppId, 0, true},
		{"/v2/users/" + primaryUserEmail, primaryUserEmail, "", 0, true},
		{"/v2/users/" + primaryUserEmail + "?epoch=-2587", primaryUserEmail, "", 0, false}, // Invalid epoch format.
		{"/v2/users/" + primaryUserEmail + "?epoch=greatepoch", primaryUserEmail, "", 0, false},
	}

	for i, test := range tests {
		rInfo := handlers.RouteInfo{
			test.path,
			"GET",
			Fake_Initializer,
			Fake_RequestHandler,
		}
		// Body is empty when invoking get user API.
		jsonBody := "{}"

		info := GetEntryV2_InitializeHandlerInfo(rInfo)

		if _, ok := info.Arg.(*pb.GetEntryRequest); !ok {
			t.Errorf("Test[%v]: info.Arg is not of type pb.GetEntryRequest", i)
		}

		r, _ := http.NewRequest(rInfo.Method, rInfo.Path, fakeJSONParserReader{bytes.NewBufferString(jsonBody)})
		mx.ServeHTTP(nil, r)
		err := info.Parser(r, &info.Arg)
		if got, want := (err == nil), test.parserNilErr; got != want {
			t.Errorf("Test[%v]: Unexpected parser err = (%v), want nil = %v", i, err, test.parserNilErr)
		}
		// If there's an error parsing, the test cannot be completed.
		// The parsing error might be expected though.
		if err != nil {
			continue
		}

		// Call JSONDecoder to simulate decoding JSON -> Proto.
		err = JSONDecoder(r, &info.Arg)
		if err != nil {
			t.Errorf("Test[%v]: Error while calling JSONDecoder, this should not happen. err: %v", i, err)
		}

		if got, want := info.Arg.(*pb.GetEntryRequest).UserId, test.userId; got != want {
			t.Errorf("Test[%v]: UserId = %v, want %v", i, got, want)
		}
		if got, want := info.Arg.(*pb.GetEntryRequest).EpochEnd, test.epoch; got != want {
			t.Errorf("Test[%v]: Epoch = %v, want %v", i, got, want)
		}

		v2 := &FakeServer{}
		srv := New(v2, testRealm)
		resp, err := info.H(srv, nil, nil)
		if err != nil {
			t.Errorf("Test[%v]: Error while calling Fake_RequestHandler, this should not happen.", i)
		}
		if got, want := (*resp).(bool), true; got != want {
			t.Errorf("Test[%v]: resp = %v, want %v.", i, got, want)
		}
	}
}

func TestListEntryHistoryV2_InitiateHandlerInfo(t *testing.T) {
	mx := mux.NewRouter()
	mx.KeepContext = true
	mx.HandleFunc("/v2/users/{"+handlers.UserIdKeyword+"}/history", Fake_HTTPHandler)

	e, _ := strconv.ParseInt(primaryTestEpoch, 10, 64)
	ps, _ := strconv.ParseInt(primaryTestPageSize, 10, 32)
	var tests = []struct {
		path         string
		userId       string
		startEpoch   int64
		pageSize     int32
		parserNilErr bool
	}{
		{"/v2/users/" + primaryUserEmail + "/history?start_epoch=" + primaryTestEpoch + "&page_size=" + primaryTestPageSize, primaryUserEmail, e, int32(ps), true},
		{"/v2/users/" + primaryUserEmail + "/history?start_epoch=" + primaryTestEpoch, primaryUserEmail, e, 0, true},
		{"/v2/users/" + primaryUserEmail + "/history?page_size=" + primaryTestPageSize, primaryUserEmail, 0, int32(ps), true},
		{"/v2/users/" + primaryUserEmail + "/history", primaryUserEmail, 0, 0, true},
		{"/v2/users/" + primaryUserEmail + "/history?start_epoch=-2587", primaryUserEmail, 0, 0, false}, // Invalid start_epoch format.
		{"/v2/users/" + primaryUserEmail + "/history?start_epoch=greatepoch", primaryUserEmail, 0, 0, false},
		{"/v2/users/" + primaryUserEmail + "/history?page_size=bigpagesize", primaryUserEmail, 0, 0, false}, // Invalid page_size format.
	}

	for i, test := range tests {
		rInfo := handlers.RouteInfo{
			test.path,
			"GET",
			Fake_Initializer,
			Fake_RequestHandler,
		}
		// Body is empty when invoking list user history API.
		jsonBody := "{}"

		info := ListEntryHistoryV2_InitializeHandlerInfo(rInfo)

		if _, ok := info.Arg.(*pb.ListEntryHistoryRequest); !ok {
			t.Errorf("Test[%v]: info.Arg is not of type pb.ListEntryHistoryRequest", i)
		}

		r, _ := http.NewRequest(rInfo.Method, rInfo.Path, fakeJSONParserReader{bytes.NewBufferString(jsonBody)})
		mx.ServeHTTP(nil, r)
		err := info.Parser(r, &info.Arg)
		if got, want := (err == nil), test.parserNilErr; got != want {
			t.Errorf("Test[%v]: Unexpected parser err = (%v), want nil = %v", i, err, test.parserNilErr)
		}
		// If there's an error parsing, the test cannot be completed.
		// The parsing error might be expected though.
		if err != nil {
			continue
		}

		// Call JSONDecoder to simulate decoding JSON -> Proto.
		err = JSONDecoder(r, &info.Arg)
		if err != nil {
			t.Errorf("Test[%v]: Error while calling JSONDecoder, this should not happen. err: %v", i, err)
		}

		if got, want := info.Arg.(*pb.ListEntryHistoryRequest).UserId, test.userId; got != want {
			t.Errorf("Test[%v]: UserId = %v, want %v", i, got, want)
		}
		if got, want := info.Arg.(*pb.ListEntryHistoryRequest).StartEpoch, test.startEpoch; got != want {
			t.Errorf("Test[%v]: StartEpoch = %v, want %v", i, got, want)
		}
		if got, want := info.Arg.(*pb.ListEntryHistoryRequest).PageSize, test.pageSize; got != want {
			t.Errorf("Test[%v]: PageSize = %v, want %v", i, got, want)
		}

		v2 := &FakeServer{}
		srv := New(v2, testRealm)
		resp, err := info.H(srv, nil, nil)
		if err != nil {
			t.Errorf("Test[%v]: Error while calling Fake_RequestHandler, this should not happen.", i)
		}
		if got, want := (*resp).(bool), true; got != want {
			t.Errorf("Test[%v]: resp = %v, want %v.", i, got, want)
		}
	}
}

func TestUpdateEntryV2_InitiateHandlerInfo(t *testing.T) {
	mx := mux.NewRouter()
	mx.KeepContext = true
	mx.HandleFunc("/v2/users/{"+handlers.UserIdKeyword+"}", Fake_HTTPHandler)

	var tests = []struct {
		path         string
		userId       string
		parserNilErr bool
	}{
		{"/v2/users/" + primaryUserEmail, primaryUserEmail, true},
	}

	for i, test := range tests {
		rInfo := handlers.RouteInfo{
			test.path,
			"PUT",
			Fake_Initializer,
			Fake_RequestHandler,
		}
		// Body is empty because it is irrelevant in this test.
		jsonBody := "{}"

		info := UpdateEntryV2_InitializeHandlerInfo(rInfo)

		if _, ok := info.Arg.(*pb.UpdateEntryRequest); !ok {
			t.Errorf("Test[%v]: info.Arg is not of type pb.UpdateEntryRequest", i)
		}

		r, _ := http.NewRequest(rInfo.Method, rInfo.Path, fakeJSONParserReader{bytes.NewBufferString(jsonBody)})
		mx.ServeHTTP(nil, r)
		err := info.Parser(r, &info.Arg)
		if got, want := (err == nil), test.parserNilErr; got != want {
			t.Errorf("Test[%v]: Unexpected parser err = (%v), want nil = %v", i, err, test.parserNilErr)
		}
		// If there's an error parsing, the test cannot be completed.
		// The parsing error might be expected though.
		if err != nil {
			continue
		}

		// Call JSONDecoder to simulate decoding JSON -> Proto.
		err = JSONDecoder(r, &info.Arg)
		if err != nil {
			t.Errorf("Test[%v]: Error while calling JSONDecoder, this should not happen. err: %v", i, err)
		}

		if got, want := info.Arg.(*pb.UpdateEntryRequest).UserId, test.userId; got != want {
			t.Errorf("Test[%v]: UserId = %v, want %v", i, got, want)
		}

		v2 := &FakeServer{}
		srv := New(v2, testRealm)
		resp, err := info.H(srv, nil, nil)
		if err != nil {
			t.Errorf("Test[%v]: Error while calling Fake_RequestHandler, this should not happen.", i)
		}
		if got, want := (*resp).(bool), true; got != want {
			t.Errorf("Test[%v]: resp = %v, want %v.", i, got, want)
		}
	}
}

func JSONDecoder(r *http.Request, v interface{}) error {
	decoder := json.NewDecoder(r.Body)
	return decoder.Decode(v)
}

func TestParseURLComponent(t *testing.T) {
	mx := mux.NewRouter()
	mx.KeepContext = true
	mx.HandleFunc("/v1/users/{"+handlers.UserIdKeyword+"}", Fake_HTTPHandler)

	var tests = []struct {
		path    string
		keyword string
		out     string
		nilErr  bool
	}{
		{"/v1/users/" + primaryUserEmail, handlers.UserIdKeyword, primaryUserEmail, true},
		{"/v1/users/" + primaryUserEmail, "random_keyword", "", false},
	}
	for i, test := range tests {
		r, _ := http.NewRequest("GET", test.path, nil)
		mx.ServeHTTP(nil, r)
		gots, gote := parseURLVariable(r, test.keyword)
		wants := test.out
		wante := test.nilErr
		if gots != wants || wante != (gote == nil) {
			t.Errorf("Test[%v]: Error while parsing User ID. Input = (%v, %v), got ('%v', %v), want ('%v', nil = %v)", i, test.path, test.keyword, gots, gote, wants, wante)
		}

	}
}

func Fake_HTTPHandler(w http.ResponseWriter, r *http.Request) {
}

func TestParseJson(t *testing.T) {
	var tests = []struct {
		inJSON    string
		outJSON   string
		outNilErr bool
	}{
		{"", "", true}, // Empty string
		{`"creation_time": "` + validTs + `"`, `"creation_time": {"seconds": ` + strconv.Itoa(tsSeconds) + `, "nanos": 0}`, true},                                                                                                                // Basic cases.
		{`{"creation_time": "` + validTs + `"}`, `{"creation_time": {"seconds": ` + strconv.Itoa(tsSeconds) + `, "nanos": 0}}`, true},                                                                                                            // Basic cases.
		{`{"signed_key":{"key": {"creation_time": "` + validTs + `"}}}`, `{"signed_key":{"key": {"creation_time": {"seconds": ` + strconv.Itoa(tsSeconds) + `, "nanos": 0}}}}`, true},                                                            // Nested case.
		{"nothing to be changed here", "nothing to be changed here", true},                                                                                                                                                                       // Nothing to be changed.
		{`"creation_time": "` + validTs + `", "creation_time": "` + validTs + `"`, `"creation_time": {"seconds": ` + strconv.Itoa(tsSeconds) + `, "nanos": 0}, "creation_time": {"seconds": ` + strconv.Itoa(tsSeconds) + `, "nanos": 0}`, true}, // Multiple keywords.
		{`"creation_time": "invalid"`, `"creation_time": "invalid"`, false},                                                                                                                                                                      // Invalid timestamp.
		{`"creation_time": ""`, `"creation_time": ""`, false},                                                                                                                                                                                    // Empty timestamp.
		{`"creation_time": "", "creation_time": ""`, `"creation_time": "", "creation_time": ""`, false},
		{`"creation_time": invalid"`, `"creation_time": invalid"`, true},                                                                                                                           // Malformed JSON, missing " at the beginning of invalid timestamp.
		{`"creation_time": "invalid`, `"creation_time": "invalid`, true},                                                                                                                           // Malformed JSON, missing " at the end of invalid timestamp.
		{`"creation_time": invalid`, `"creation_time": invalid`, true},                                                                                                                             // Malformed JSON, missing " at the beginning and end of invalid timestamp.
		{`"creation_time": "` + validTs, `"creation_time": "` + validTs, true},                                                                                                                     // Malformed JSON, missing " at the end of valid timestamp.
		{`creation_time: "invalid"`, `creation_time: "invalid"`, false}, {`{creation_time: "` + validTs + `"}`, `{creation_time: {"seconds": ` + strconv.Itoa(tsSeconds) + `, "nanos": 0}}`, true}, // keyword is not surrounded by "", in four cases: invalid timestamp, basic, nested and multiple keywords.
		{`{"signed_key":{"key": {creation_time: "` + validTs + `"}}}`, `{"signed_key":{"key": {creation_time: {"seconds": ` + strconv.Itoa(tsSeconds) + `, "nanos": 0}}}}`, true},
		{`creation_time: "` + validTs + `", "creation_time": "` + validTs + `"`, `creation_time: {"seconds": ` + strconv.Itoa(tsSeconds) + `, "nanos": 0}, "creation_time": {"seconds": ` + strconv.Itoa(tsSeconds) + `, "nanos": 0}`, true}, // Only first keyword is not surrounded by "".
		{`{"signed_key":{"key": {"creation_time": ` + validTs + `", app_id: "` + primaryTestAppId + `"}}}`, `{"signed_key":{"key": {"creation_time": ` + validTs + `", app_id: "` + primaryTestAppId + `"}}}`, true},                         // Timestamp is not surrounded by "" and there's other keys and  values after.
	}

	for i, test := range tests {
		r, _ := http.NewRequest("", "", fakeJSONParserReader{bytes.NewBufferString(test.inJSON)})
		err := parseJSON(r, "creation_time")
		if test.outNilErr != (err == nil) {
			t.Errorf("Test[%v]: Unexpected JSON parser err = (%v), want nil = %v", i, err, test.outNilErr)
		}
		buf := new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		if got, want := buf.String(), test.outJSON; got != want {
			t.Errorf("Test[%v]: Out JSON=\n[%v], want \n[%v]", i, got, want)
		}
	}
}
