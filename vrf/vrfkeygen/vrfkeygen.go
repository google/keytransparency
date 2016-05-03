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

// package main generates a VRF key pair and saves them to disk.
package main

import (
	"flag"
	"log"
	"os"

	"github.com/gdbelvin/e2e-key-server/vrf/p256"
)

var (
	prvPath = flag.String("privkey", "private_vrf_key.dat", "Output path for VRF private key.")
	pubPath = flag.String("pubkey", "public_vrf_key.dat", "Output path for VRF public key.")
)

func main() {
	priv, pub := p256.GenerateKey()

	prvFile, err := os.Create(*prvPath)
	if err != nil {
		log.Fatalf("Failed creating private key file: %v: %v", *prvPath, err)
	}
	defer prvFile.Close()
	if _, err := prvFile.Write(priv.Bytes()); err != nil {
		log.Fatalf("Failed writing private key file: %v: %v", *prvPath, err)
	}

	pubFile, err := os.Create(*pubPath)
	if err != nil {
		log.Fatalf("Failed creating public key file: %v: %v", *pubPath, err)
	}
	defer pubFile.Close()
	if _, err := pubFile.Write(pub.Bytes()); err != nil {
		log.Fatalf("Failed writing public key file: %v: %v", *pubPath, err)
	}
}
