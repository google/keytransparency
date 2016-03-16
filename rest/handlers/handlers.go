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

package handlers

import (
	"net/http"

	context "golang.org/x/net/context"
)

const (
	UserIdKeyword = "user_id"
)

// URLParser parses a URL and stores the results in a protobuf structure that
// will be passed to the API call. An error is returned if parsing returns
// an error.
type URLParser func(*http.Request, *interface{}) error

// RequestHandler returns API call results of a server instance, context and
// API arguments. It returns an error of the API call returns an error.
type RequestHandler func(interface{}, context.Context, interface{}) (*interface{}, error)

// InitializeHandlerInfo generates and initializes HandlerInfo.
type InitializeHandlerInfo func(RouteInfo) *HandlerInfo

// HandlerInfo contains information related to the API handler.
type HandlerInfo struct {
	// API call handler.
	H RequestHandler
	// Argument to be passed to the API request handler function.
	Arg interface{}
	// Function that parses URL params.
	Parser URLParser
}

// RouteInfo contains routes information of v1 RESTful APIs.
type RouteInfo struct {
	// API Path.
	Path string
	// Request method, e.g. GET, POST, etc.
	Method string
	// The function that initializes the appropriate HandlerInfo.
	Initializer InitializeHandlerInfo
	// API handler.
	Handler RequestHandler
}
