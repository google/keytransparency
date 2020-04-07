// Copyright 2020 Google Inc. All Rights Reserved.
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

package vrf

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestI2OSP(t *testing.T) {
	for i, tc := range []struct {
		x         int64
		xLen      uint
		want      []byte
		wantPanic bool
	}{
		{x: 1, xLen: 1, want: []byte{0x01}},
		{x: 2, xLen: 1, want: []byte{0x02}},
		{x: 2, xLen: 2, want: []byte{0, 2}},
		{x: 256, xLen: 8, want: []byte{0, 0, 0, 0, 0, 0, 1, 0}},
		{x: 256, xLen: 1, wantPanic: true},
		{x: 255, xLen: 1, want: []byte{0xff}},
	} {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			defer func() {
				r := recover()
				if panicked := r != nil; panicked != tc.wantPanic {
					t.Errorf("Panicked: %v, wantPanic %v", r, tc.wantPanic)
				}
			}()
			if got := i2osp(big.NewInt(tc.x), tc.xLen); !bytes.Equal(got, tc.want) {
				t.Errorf("I2OSP(%v, %v): %v, want %v", tc.x, tc.xLen, got, tc.want)
			}
		})
	}
}

func TestSEG1EncodeDecode(t *testing.T) {
	c := elliptic.P256()
	_, Ax, Ay, err := elliptic.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	b := secg1EncodeCompressed(c, Ax, Ay)
	Bx, By, err := secg1Decode(c, b)
	if err != nil {
		t.Fatal(err)
	}
	if Bx.Cmp(Ax) != 0 {
		t.Fatalf("Bx: %v, want %v", Bx, Ax)
	}
	if By.Cmp(Ay) != 0 {
		t.Fatalf("By: %v, want %v", By, Ay)
	}
}
