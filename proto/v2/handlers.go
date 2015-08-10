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

package google_security_e2ekeys_v2

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/google/e2e-key-server/rest/handlers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	context "golang.org/x/net/context"
)

// HandlerV2 handles v2 API requests, call the appropriate API handler, and
// return an error if the request cannot be parsed/decoded correctly or
// the API call returns an error.
// TODO: I wish this could be code generated.
func HandlerV2(srv interface{}, ctx context.Context, w http.ResponseWriter, r *http.Request, info *handlers.HandlerInfo) error {
	// Parsing URL params and JSON. Parsing should always be called before
	// attemping decoding JSON body because parsing will convert timestamp
	// to the appropriate format.
	err := info.Parser(r, &info.Arg)
	if err != nil {
		return err
	}

	// Json -> Proto.
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&info.Arg)
	if err != nil && err != io.EOF {
		return grpc.Errorf(codes.InvalidArgument, "decoding error:", err)
	}

	// Calling the actual API handler.
	resp, err := info.H(srv, ctx, info.Arg)
	if err != nil {
		return err
	}

	// Content-Type is always application/json.
	w.Header().Set("Content-Type", "application/json")
	// Proto -> json.
	encoder := json.NewEncoder(w)
	encoder.Encode(resp)
	return nil
}
