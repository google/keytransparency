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

package kt

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/google/keytransparency/core/crypto/commitments"
	"github.com/google/keytransparency/core/crypto/keymaster"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/crypto/vrf/p256"
	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"

	"github.com/golang/protobuf/proto"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/crypto/keys/pem"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/hashers"
	"github.com/google/trillian/merkle/maphasher"
	_ "github.com/google/trillian/merkle/objhasher" // Used to init the package so that the hasher gets registered (needed by the bGetVerifierFromParams function)
	"golang.org/x/net/context"
)

var (
	// ErrNilProof occurs when the provided GetEntryResponse contains a nil proof.
	ErrNilProof = errors.New("nil proof")

	// Vlog is the verbose logger. By default it outputs to /dev/null.
	Vlog = log.New(ioutil.Discard, "", 0)
)

// Verifier is a client helper library for verifying request and responses.
type Verifier struct {
	vrf         vrf.PublicKey
	hasher      hashers.MapHasher
	mapPubKey   crypto.PublicKey
	logVerifier client.LogVerifier
}

// New creates a new instance of the client verifier.
func New(vrf vrf.PublicKey,
	hasher hashers.MapHasher,
	mapPubKey crypto.PublicKey,
	logVerifier client.LogVerifier) *Verifier {
	return &Verifier{
		vrf:         vrf,
		hasher:      hasher,
		mapPubKey:   mapPubKey,
		logVerifier: logVerifier,
	}
}

// VerifyGetEntryResponse verifies GetEntryResponse:
//  - Verify commitment.
//  - Verify VRF.
//  - Verify tree proof.
//  - Verify signature.
//  - Verify consistency proof from log.Root().
//  - Verify inclusion proof.
func (v *Verifier) VerifyGetEntryResponse(ctx context.Context, userID, appID string,
	trusted *trillian.SignedLogRoot, in *tpb.GetEntryResponse) error {
	// Unpack the merkle tree leaf value.
	entry := new(tpb.Entry)
	if err := proto.Unmarshal(in.GetLeafProof().GetLeaf().GetLeafValue(), entry); err != nil {
		return err
	}

	// If this is not a proof of absence, verify the connection between
	// profileData and the commitment in the merkle tree leaf.
	if in.GetCommitted() != nil {
		commitment := entry.GetCommitment()
		data := in.GetCommitted().GetData()
		nonce := in.GetCommitted().GetKey()
		if err := commitments.Verify(userID, appID, commitment, data, nonce); err != nil {
			Vlog.Printf("✗ Commitment verification failed.")
			return fmt.Errorf("commitments.Verify(): %v", err)
		}
	}
	Vlog.Printf("✓ Commitment verified.")

	index, err := v.vrf.ProofToHash(vrf.UniqueID(userID, appID), in.GetVrfProof())
	if err != nil {
		Vlog.Printf("✗ VRF verification failed.")
		return fmt.Errorf("vrf.ProofToHash(%v, %v): %v", userID, appID, err)
	}
	Vlog.Printf("✓ VRF verified.")

	leafProof := in.GetLeafProof()
	if leafProof == nil {
		return ErrNilProof
	}

	leaf := leafProof.GetLeaf().GetLeafValue()
	proof := leafProof.GetInclusion()
	expectedRoot := in.GetSmr().GetRootHash()
	mapID := in.GetSmr().GetMapId()
	if err := merkle.VerifyMapInclusionProof(mapID, index[:], leaf, expectedRoot, proof, v.hasher); err != nil {
		Vlog.Printf("✗ Sparse tree proof verification failed.")
		return fmt.Errorf("VerifyMapInclusionProof(): %v", err)
	}
	Vlog.Printf("✓ Sparse tree proof verified.")

	// SignedMapRoot contains its own signature. To verify, we need to create a local
	// copy of the object and return the object to the state it was in when signed
	// by removing the signature from the object.
	smr := *in.GetSmr()
	smr.Signature = nil // Remove the signature from the object to be verified.
	if err := tcrypto.VerifyObject(v.mapPubKey, smr, in.GetSmr().GetSignature()); err != nil {
		Vlog.Printf("✗ Signed Map Head signature verification failed.")
		return fmt.Errorf("sig.Verify(SMR): %v", err)
	}
	Vlog.Printf("✓ Signed Map Head signature verified.")

	// Verify consistency proof between root and newroot.
	// TODO(gdbelvin): Gossip root.
	if err := v.logVerifier.VerifyRoot(trusted, in.GetLogRoot(), in.GetLogConsistency()); err != nil {
		return fmt.Errorf("VerifyRoot(%v, %v): %v", in.GetLogRoot(), in.GetLogConsistency(), err)
	}
	Vlog.Printf("✓ Log root updated.")
	trusted = in.GetLogRoot()

	// Verify inclusion proof.
	b, err := json.Marshal(in.GetSmr())
	if err != nil {
		return fmt.Errorf("json.Marshal(): %v", err)
	}
	logLeafIndex := in.GetSmr().GetMapRevision()
	if err := v.logVerifier.VerifyInclusionAtIndex(trusted, b, logLeafIndex,
		in.GetLogInclusion()); err != nil {
		return fmt.Errorf("VerifyInclusionAtIndex(%s, %v, _): %v",
			b, in.GetSmr().GetMapRevision(), err)
	}
	Vlog.Printf("✓ Log inclusion proof verified.")
	return nil
}

type BVerifierParams struct {
	MapID     int64
	VrfPubPEM []byte
	KtPEM     []byte
	LogPEM    []byte
}

func NewBVerifierParams(MapID int64, VrfPubPEM, KtPEM, LogPEM []byte) *BVerifierParams {
	// Note: byte arrays need to be explicitly cloned due to some gobind limitations.
	cVrfPubPEM := make([]byte, len(VrfPubPEM))
	copy(cVrfPubPEM, VrfPubPEM)
	cKtPEM := make([]byte, len(KtPEM))
	copy(cKtPEM, KtPEM)
	cLogPEM := make([]byte, len(LogPEM))
	copy(cLogPEM, LogPEM)

	return &BVerifierParams{MapID, cVrfPubPEM, cKtPEM, cLogPEM}
}

func bGetVerifierFromParams(p BVerifierParams) (*Verifier, error) {

	vrf, err := p256.NewVRFVerifierFromPEM(p.VrfPubPEM)
	if err != nil {
		return nil, fmt.Errorf("Error parsing vrf public key: %v", err)
	}

	// TODO this maphasher implementation is ok for debug only. Update.
	maphasher := maphasher.Default

	// Verifier
	ver, err := keymaster.NewVerifierFromPEM(p.KtPEM)
	if err != nil {
		return nil, fmt.Errorf("Error creating verifier from PEM encoded key: %v", err)
	}

	// log can verify Trillian Logs.
	logPubKey, err := pem.UnmarshalPublicKey(string(p.LogPEM))
	if err != nil {
		return nil, fmt.Errorf("Failed to open public key %v: %v", logPubKey, err)
	}
	hasher, err := hashers.NewLogHasher(trillian.HashStrategy_OBJECT_RFC6962_SHA256)
	if err != nil {
		return nil, fmt.Errorf("Failed retrieving LogHasher from registry: %v", err)
	}
	log := client.NewLogVerifier(hasher, logPubKey)

	return New(vrf, maphasher, ver, log), nil
}

func BVerifyGetEntryResponse(verParam *BVerifierParams, userID string, appID string,
	trusted_trillianSignedLogRoot []byte, in_tpbGetEntryResponse []byte) error {

	v, err := bGetVerifierFromParams(*verParam)
	if err != nil {
		return fmt.Errorf("Couldn't build verifier: %v", err)
	}

	trusted := &trillian.SignedLogRoot{}
	err = proto.Unmarshal(trusted_trillianSignedLogRoot, trusted)
	if err != nil {
		return err
	}

	in := &tpb.GetEntryResponse{}
	err = proto.Unmarshal(in_tpbGetEntryResponse, in)
	if err != nil {
		return err
	}

	// TODO(amarcedone) Is context.Background() appropriate here?
	return v.VerifyGetEntryResponse(context.Background(), userID, appID, trusted, in)
}
