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

package p256

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"sync"
	"testing"

	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/google/keytransparency/core/testdata"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"

	tpb "github.com/google/keytransparency/core/testdata/transcript_go_proto"
	_ "github.com/google/trillian/crypto/keys/der/proto"
)

const (
	// openssl ecparam -name prime256v1 -genkey -out p256-key.pem
	privKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGbhE2+z8d5lHzb0gmkS78d86gm5gHUtXCpXveFbK3pcoAoGCCqGSM49
AwEHoUQDQgAEUxX42oxJ5voiNfbjoz8UgsGqh1bD1NXK9m8VivPmQSoYUdVFgNav
csFaQhohkiCEthY51Ga6Xa+ggn+eTZtf9Q==
-----END EC PRIVATE KEY-----`
	// openssl ec -in p256-key.pem -pubout -out p256-pubkey.pem
	pubKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUxX42oxJ5voiNfbjoz8UgsGqh1bD
1NXK9m8VivPmQSoYUdVFgNavcsFaQhohkiCEthY51Ga6Xa+ggn+eTZtf9Q==
-----END PUBLIC KEY-----`
)

func TestH1(t *testing.T) {
	for i := 0; i < 10000; i++ {
		m := make([]byte, 100)
		if _, err := rand.Read(m); err != nil {
			t.Fatalf("Failed generating random message: %v", err)
		}
		x, y := H1(m)
		if x == nil {
			t.Errorf("H1(%v)=%v, want curve point", m, x)
		}
		if got := curve.Params().IsOnCurve(x, y); !got {
			t.Errorf("H1(%v)=[%v, %v], is not on curve", m, x, y)
		}
	}
}

func TestH2(t *testing.T) {
	l := 32
	for i := 0; i < 10000; i++ {
		m := make([]byte, 100)
		if _, err := rand.Read(m); err != nil {
			t.Fatalf("Failed generating random message: %v", err)
		}
		x := H2(m)
		if got := len(x.Bytes()); got < 1 || got > l {
			t.Errorf("len(h2(%v)) = %v, want: 1 <= %v <= %v", m, got, got, l)
		}
	}
}

func TestNewFromWrappedKey(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		desc               string
		wantFromWrappedErr bool
		spec               *keyspb.Specification
		keygen             keys.ProtoGenerator
	}{
		{
			desc: "DER with ECDSA spec",
			spec: &keyspb.Specification{
				Params: &keyspb.Specification_EcdsaParams{
					EcdsaParams: &keyspb.Specification_ECDSA{
						Curve: keyspb.Specification_ECDSA_P256,
					},
				},
			},
			keygen: func(ctx context.Context, spec *keyspb.Specification) (proto.Message, error) {
				return der.NewProtoFromSpec(spec)
			},
		},
		{
			desc:               "DER with Non-ECDSA spec",
			wantFromWrappedErr: true,
			spec: &keyspb.Specification{
				Params: &keyspb.Specification_RsaParams{
					RsaParams: &keyspb.Specification_RSA{Bits: 2048},
				},
			},
			keygen: func(ctx context.Context, spec *keyspb.Specification) (proto.Message, error) {
				return der.NewProtoFromSpec(spec)
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			// Generate VRF key.
			wrapped, err := tc.keygen(ctx, tc.spec)
			if err != nil {
				t.Fatalf("keygen failed: %v", err)
			}
			vrfPriv, err := NewFromWrappedKey(ctx, wrapped)
			if got, want := err != nil, tc.wantFromWrappedErr; got != want {
				t.Errorf("NewFromWrappedKey (): %v, want err: %v", err, want)
			}
			if err != nil {
				return
			}

			vrfPubDER, err := der.MarshalPublicKey(vrfPriv.Public())
			if err != nil {
				t.Fatalf("MarshalPublicKey failed: %v", err)
			}
			vrfPub, err := NewVRFVerifierFromRawKey(vrfPubDER)
			if err != nil {
				t.Fatalf("NewVRFVerifierFromRawKey(): %v", err)
			}
			// Test that the public and private components match.
			m := []byte("foobar")
			indexA, proof := vrfPriv.Evaluate(m)
			indexB, err := vrfPub.ProofToHash(m, proof)
			if err != nil {
				t.Fatalf("ProofToHash(): %v", err)
			}
			if got, want := indexB, indexA; got != want {
				t.Errorf("ProofToHash(%s, %x): %x, want %x", m, proof, got, want)
			}
		})
	}
}

func TestVRF(t *testing.T) {
	k, pk := GenerateKey()

	m1 := []byte("data1")
	m2 := []byte("data2")
	m3 := []byte("data2")
	index1, proof1 := k.Evaluate(m1)
	index2, proof2 := k.Evaluate(m2)
	index3, proof3 := k.Evaluate(m3)
	for _, tc := range []struct {
		m     []byte
		index [32]byte
		proof []byte
		err   error
	}{
		{m1, index1, proof1, nil},
		{m2, index2, proof2, nil},
		{m3, index3, proof3, nil},
		{m3, index3, proof2, nil},
		{m3, index3, proof1, ErrInvalidVRF},
	} {
		index, err := pk.ProofToHash(tc.m, tc.proof)
		if got, want := err, tc.err; got != want {
			t.Errorf("ProofToHash(%s, %x): %v, want %v", tc.m, tc.proof, got, want)
		}
		if err != nil {
			continue
		}
		if got, want := index, tc.index; got != want {
			t.Errorf("ProofToInex(%s, %x): %x, want %x", tc.m, tc.proof, got, want)
		}
	}
}

func BenchmarkEvaluate(b *testing.B) {
	k, _ := GenerateKey()
	m1 := []byte("data1")
	for _, routines := range []int{1, 2, 4, 8, 16, 32, 64, 128} {
		b.Run(fmt.Sprintf("%d goroutines", routines), func(b *testing.B) {
			var wg sync.WaitGroup
			defer wg.Wait()
			for i := 0; i < routines; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for n := 0; n < b.N/routines; n++ {
						k.Evaluate(m1)
					}
				}()
			}
		})
	}
}

// Test vectors in core/testdata are generated by running
// go generate ./core/testdata
func TestProofToHash(t *testing.T) {
	transcript, err := testdata.ReadTranscript("TestEmptyGetAndUpdate")
	if err != nil {
		t.Fatal(err)
	}

	pk, err := NewVRFVerifierFromRawKey(transcript.GetDirectory().GetVrf().GetDer())
	if err != nil {
		t.Fatalf("NewVRFVerifier failure: %v", err)
	}

	for _, rpc := range transcript.Actions {
		t.Run(rpc.Desc, func(t *testing.T) {
			switch pair := rpc.ReqRespPair.(type) {
			case *tpb.Action_GetUser:
				userID := pair.GetUser.Request.UserId
				vrfProof := pair.GetUser.Response.GetLeaf().GetVrfProof()
				if _, err := pk.ProofToHash([]byte(userID), vrfProof); err != nil {
					t.Errorf("ProofToHash(): %v)", err)
				}
			default:
				t.Fatalf("Unknown ReqRespPair: %T", pair)
			}
		})
	}
}

func TestReadFromOpenSSL(t *testing.T) {
	for _, tc := range []struct {
		priv string
		pub  string
	}{
		{privKey, pubKey},
	} {
		// Private VRF Key
		signer, err := NewVRFSignerFromPEM([]byte(tc.priv))
		if err != nil {
			t.Errorf("NewVRFSigner failure: %v", err)
		}

		// Public VRF key
		verifier, err := NewVRFVerifierFromPEM([]byte(tc.pub))
		if err != nil {
			t.Errorf("NewVRFSigner failure: %v", err)
		}

		// Evaluate and verify.
		m := []byte("M")
		_, proof := signer.Evaluate(m)
		if _, err := verifier.ProofToHash(m, proof); err != nil {
			t.Errorf("Failed verifying VRF proof")
		}
	}
}

func TestRightTruncateProof(t *testing.T) {
	k, pk := GenerateKey()

	data := []byte("data")
	_, proof := k.Evaluate(data)
	proofLen := len(proof)
	for i := 0; i < proofLen; i++ {
		proof = proof[:len(proof)-1]
		if _, err := pk.ProofToHash(data, proof); err == nil {
			t.Errorf("Verify unexpectedly succeeded after truncating %v bytes from the end of proof", i)
		}
	}
}

func TestLeftTruncateProof(t *testing.T) {
	k, pk := GenerateKey()

	data := []byte("data")
	_, proof := k.Evaluate(data)
	proofLen := len(proof)
	for i := 0; i < proofLen; i++ {
		proof = proof[1:]
		if _, err := pk.ProofToHash(data, proof); err == nil {
			t.Errorf("Verify unexpectedly succeeded after truncating %v bytes from the beginning of proof", i)
		}
	}
}

func TestBitFlip(t *testing.T) {
	k, pk := GenerateKey()

	data := []byte("data")
	_, proof := k.Evaluate(data)
	for i := 0; i < len(proof)*8; i++ {
		// Flip bit in position i.
		if _, err := pk.ProofToHash(data, flipBit(proof, i)); err == nil {
			t.Errorf("Verify unexpectedly succeeded after flipping bit %v of vrf", i)
		}
	}
}

func flipBit(a []byte, pos int) []byte {
	index := int(math.Floor(float64(pos) / 8))
	b := a[index]
	b ^= (1 << uint(math.Mod(float64(pos), 8.0)))

	var buf bytes.Buffer
	buf.Write(a[:index])
	buf.Write([]byte{b})
	buf.Write(a[index+1:])
	return buf.Bytes()
}

func TestVectors(t *testing.T) {
	k, err := NewVRFSignerFromPEM([]byte(privKey))
	if err != nil {
		t.Errorf("NewVRFSigner failure: %v", err)
	}
	pk, err := NewVRFVerifierFromPEM([]byte(pubKey))
	if err != nil {
		t.Errorf("NewVRFSigner failure: %v", err)
	}
	for _, tc := range []struct {
		m     []byte
		index [32]byte
	}{
		{
			m:     []byte("test"),
			index: h2i("1af0a7e3d9a96a71be6257cf4ad1a0ffdec57e9959b2eafc4673a6c31241fc9f"),
		},
		{
			m:     nil,
			index: h2i("2ebac3669807f474f4d49891a1d0b2fba8e966f945ac01cbfffb3bb48627e67d"),
		},
	} {
		index, proof := k.Evaluate(tc.m)
		if got, want := index, tc.index; got != want {
			t.Errorf("Evaluate(%s).Index: %x, want %x", tc.m, got, want)
		}
		index2, err := pk.ProofToHash(tc.m, proof)
		if err != nil {
			t.Errorf("ProofToHash(%s): %v", tc.m, err)
		}
		if got, want := index2, index; got != want {
			t.Errorf("ProofToHash(%s): %x, want %x", tc.m, got, want)
		}
	}
}

func h2i(h string) [32]byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic("Invalid hex")
	}
	var i [32]byte
	copy(i[:], b)
	return i
}
