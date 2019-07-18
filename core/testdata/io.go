// Copyright 2018 Google Inc. All Rights Reserved.
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

package testdata

import (
	"fmt"
	"go/build"
	"os"
	"path"
	"path/filepath"

	"github.com/golang/protobuf/jsonpb"

	tpb "github.com/google/keytransparency/core/testdata/transcript_go_proto"
)

// packagePath returns the on-disk path of *this* package.
func packagePath() (string, error) {
	basePkg := "github.com/google/keytransparency/core/testdata"
	p, err := build.Default.Import(basePkg, "", build.FindOnly)
	if err != nil {
		return "", err
	}
	return p.Dir, nil
}

// ReadTranscript returns the test vectors for the requested test name.
func ReadTranscript(testName string) (*tpb.Transcript, error) {
	selfPath, err := packagePath()
	if err != nil {
		return nil, err
	}
	relPath := path.Join(selfPath, fmt.Sprintf("%v.json", testName))
	absPath, err := filepath.Abs(relPath)
	if err != nil {
		return nil, err
	}
	transcriptFile := absPath

	f, err := os.Open(transcriptFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var transcript tpb.Transcript
	if err := jsonpb.Unmarshal(f, &transcript); err != nil {
		return nil, fmt.Errorf("jsonpb.Unmarshal(): %v", err)
	}
	return &transcript, nil
}

// WriteTranscript saves the transcript to the testdata directory.
func WriteTranscript(testName string, t *tpb.Transcript) error {
	marshaler := &jsonpb.Marshaler{Indent: "\t"}

	selfPath, err := packagePath()
	if err != nil {
		return err
	}
	// Output all key material needed to verify the test vectors.
	testFile := path.Join(selfPath, fmt.Sprintf("%v.json", testName))
	f, err := os.Create(testFile)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := marshaler.Marshal(f, t); err != nil {
		return fmt.Errorf("jsonpb.Marshal(): %v", err)
	}
	return nil
}
