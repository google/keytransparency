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

package handlers

import (
	"net/url"

	context "golang.org/x/net/context"
)

// Function signature that parses URL parameters
// *interface{} is a protocol buffer generated struct that
// will be passed to the v1 API call.
type URLParser func(*url.URL, *interface{}) error

// Function signature of the actual API call
// First interface{} parameter is the server instance
// Third interface{} parameter is a protocol buffer generated struct
// compatible with the API call. Same for the returned *interface{}
type RequestHandler func(interface{}, context.Context, interface{}) (*interface{}, error)

// Function that generates and initializes HandlerInfo
type InitializeHandlerInfo func(RouteInfo) *HandlerInfo

// Contains information related to the API handler
type HandlerInfo struct {
	// API call handler
	H RequestHandler
	// Argument to be passed to the API request handler function
	Arg interface{}
	// Function that parses URL params
	Parser URLParser
}

// Struct containing routes info
type RouteInfo struct {
	// API Path
	Path string
	// UserId index in the path components
	// TODO(cesarghali): it's better if the index can be detected automatically
	UserIdIndex int
	// Request method, e.g. GET, POST, etc
	Method string
	// Refer to the function that initialize the request
	// rest/handlers/handlers.go:HandlerInfo
	Initializer InitializeHandlerInfo
	// API handler
	Handler RequestHandler
}
