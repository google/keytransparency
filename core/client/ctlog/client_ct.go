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

package ctlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	ct "github.com/google/certificate-transparency/go"
	logclient "github.com/google/certificate-transparency/go/client"
	"github.com/google/certificate-transparency/go/merkletree"
	"golang.org/x/net/context"

	"github.com/google/key-transparency/core/proto/ctmap"
)

var (
	// Vlog is the verbose logger. By default it outputs to /dev/null.
	Vlog = log.New(ioutil.Discard, "", 0)

	hasher = func(b []byte) []byte {
		h := sha256.Sum256(b)
		return h[:]
	}
)

// Verifier represents an append-only log.
type Verifier interface {
	// VerifySCT ensures that a SignedMapHead has been properly included in
	// a Certificate Transparency append-only log. If the inclusion proof
	// cannot be immediately verified, it is added to a list that
	// VerifySavedSCTs can check at a later point.
	VerifySCT(smh *ctmap.SignedMapHead, sct *ct.SignedCertificateTimestamp) error
	// VerifySavedSCTs attempts to complete any unverified proofs against
	// the current, hopefully fresher, SignedTreeHead. Completed proofs are
	// removed.  Proofs that cannot be completed yet remain saved. Failed
	// proofs are returned.
	VerifySavedSCTs() []SCTEntry
	// UpdateSTH advances the current SignedTreeHead and verifies a
	// consistency proof between the current and the new STH.
	UpdateSTH() error
	// Save unverified SCTs to disk.
	Save(file string) error
	// Load unverified SCTs from disk.
	Restore(file string) error
}

// Log represents a Certificate Transparency append-only log.
type Log struct {
	MMD   time.Duration     // Maximum merge delay.
	STH   ct.SignedTreeHead // Current trusted STH.
	scts  []SCTEntry        // Unverified SCTs.
	ver   *ct.SignatureVerifier
	mtv   merkletree.MerkleVerifier
	ctlog *logclient.LogClient
}

// SCTEntry contains enough data to verify an SCT after the fact.
type SCTEntry struct {
	Sct *ct.SignedCertificateTimestamp
	Smh *ctmap.SignedMapHead
}

// New produces a new CT log verification client.
func New(pem []byte, logURL string) (*Log, error) {
	pk, _, _, err := ct.PublicKeyFromPEM(pem)
	if err != nil {
		return nil, fmt.Errorf("error reading public key from pem: %v", err)
	}
	ver, err := ct.NewSignatureVerifier(pk)
	if err != nil {
		return nil, err
	}
	return &Log{
		MMD:   24 * time.Hour,
		mtv:   merkletree.NewMerkleVerifier(hasher),
		ver:   ver,
		ctlog: logclient.New(logURL, nil),
		scts:  make([]SCTEntry, 0),
	}, nil
}

// timestamp returns the time indicated by timestamp, which is the time measured
// since the epoch (January 1, 1970, 00:00 UTC), ignoring leap seconds, in
// milliseconds.
func timestamp(timestamp uint64) time.Time {
	return time.Unix(
		int64(timestamp)/1000,               // Millisecond to seconds.
		(int64(timestamp)%1000)*(1000*1000), // Millisecond to nsecs.
	)
}

// VerifySCT ensures that SMH has been properly included in the append only log.
func (l *Log) VerifySCT(smh *ctmap.SignedMapHead, sct *ct.SignedCertificateTimestamp) error {
	requireSCT := timestamp(sct.Timestamp).Add(l.MMD)
	STHTime := timestamp(l.STH.Timestamp)
	// Is the current STH new enough to verify the SCT?
	// Most of the time, this will not be the case.
	if STHTime.After(requireSCT) {
		return l.inclusionProof(&l.STH, smh, sct.Timestamp)
	}

	// Optional: Is an inclusion proof required to be available?
	// Most of the time this will not be the case.
	// Disabled to facilitate testing without referring to time.Now()
	// if time.Now().After(requireSCT) {

	// Update the current STH and try again.
	if err := l.UpdateSTH(); err != nil {
		return err
	}
	STHTime = timestamp(l.STH.Timestamp)
	if STHTime.After(requireSCT) {
		return l.inclusionProof(&l.STH, smh, sct.Timestamp)
	}

	// Save the SCT signature and verify later.
	e := ct.LogEntry{Leaf: *ct.CreateJSONMerkleTreeLeaf(smh, sct.Timestamp)}
	if err := l.ver.VerifySCTSignature(*sct, e); err != nil {
		Vlog.Printf("CT ✗ SCT signature verification failed.")
		return err
	}
	Vlog.Printf("CT ✓ SCT signature verified. Saving SCT for future inclusion proof verification.")
	l.scts = append(l.scts, SCTEntry{sct, smh}) // Add to SCT waitlist.
	return nil
}

// VerifySavedSCTs returns a list of SCTs that failed validation against the current
// STH. If this list is non-nil, the security guarantees of the append-only log
// have been compromised.  TODO: have the client call this on some schedule
// after updating the STH.
func (l *Log) VerifySavedSCTs() []SCTEntry {
	invalidSCTs := l.scts[:0]
	unvalidatedSCTs := l.scts[:0]

	STHTime := timestamp(l.STH.Timestamp)
	// Iterate through saved SCTs. Verify all the ones that are required to
	// be included in the new STH.
	before := len(l.scts)
	for _, v := range l.scts {
		requireSCT := timestamp(v.Sct.Timestamp).Add(l.MMD)
		if STHTime.After(requireSCT) {
			if err := l.inclusionProof(&l.STH, v.Smh, v.Sct.Timestamp); err != nil {
				invalidSCTs = append(invalidSCTs, v)
			}
		} else {
			unvalidatedSCTs = append(unvalidatedSCTs, v)
		}
	}
	l.scts = unvalidatedSCTs
	after := len(l.scts)
	Vlog.Printf("CT Verified %v/%v SCTs. %v Remaining.", before-after, before, after)
	return invalidSCTs
}

// UpdateSTH ensures that STH is at least 1 MMD from Now().
func (l *Log) UpdateSTH() error {
	// Fetch STH.
	sth, err := l.ctlog.GetSTH()
	if err != nil {
		return err
	}
	// Verify signature.
	if err := l.ver.VerifySTHSignature(*sth); err != nil {
		Vlog.Printf("CT ✗ STH signature verification failed.")
		return err
	}
	Vlog.Printf("CT ✓ STH signature verified.")

	// Implicity trust the first STH we get.
	if l.STH.TreeSize != 0 {
		// Get consistency proof.
		ctx := context.Background()
		proof, err := l.ctlog.GetSTHConsistency(ctx, l.STH.TreeSize, sth.TreeSize)
		if err != nil {
			Vlog.Printf("CT ✗ Consistency proof fetch failed.")
			return err
		}
		// Verify consistency proof.
		if err := l.mtv.VerifyConsistencyProof(int64(l.STH.TreeSize),
			int64(sth.TreeSize), l.STH.SHA256RootHash[:],
			sth.SHA256RootHash[:], proof); err != nil {
			Vlog.Printf("CT ✗ Consistency proof verification failed.")
			return err
		}
		Vlog.Printf("CT ✓ Consistency proof verified.")
	}
	// Update trusted sth.
	l.STH = *sth
	Vlog.Printf("CT   New trusted STH: %v", timestamp(l.STH.Timestamp).Local())
	return nil
}

// inclusionProof fetches and verifies an inclusion proof from the CT server.
func (l *Log) inclusionProof(sth *ct.SignedTreeHead, smh *ctmap.SignedMapHead, timestamp uint64) error {
	// Get inclusion proof by hash
	leaf := ct.CreateJSONMerkleTreeLeaf(smh, timestamp)
	leafBuff := new(bytes.Buffer)
	if err := ct.SerializeMerkleTreeLeaf(leafBuff, leaf); err != nil {
		return err
	}
	treehasher := merkletree.NewTreeHasher(hasher)
	hash := treehasher.HashLeaf(leafBuff.Bytes())
	ctx := context.Background()
	proof, err := l.ctlog.GetProofByHash(ctx, hash, sth.TreeSize)
	if err != nil {
		return err
	}
	// Verify inclusion proof.
	v := merkletree.NewMerkleVerifier(hasher)
	if err := v.VerifyInclusionProof(proof.LeafIndex, int64(sth.TreeSize),
		proof.AuditPath, sth.SHA256RootHash[:], leafBuff.Bytes()); err != nil {
		Vlog.Printf("CT ✗ inclusion proof verification failed.")
		return err
	}
	Vlog.Printf("CT ✓ inclusion proof verified.")
	return nil
}

// Save persists unverified SCTs to disk
func (l *Log) Save(file string) error {
	var d bytes.Buffer
	enc := gob.NewEncoder(&d)
	err := enc.Encode(l.scts)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(file, d.Bytes(), 0644); err != nil {
		return err
	}
	return nil
}

// Restore restores a verifier's state from disk.
func (l *Log) Restore(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := gob.NewDecoder(f)
	if err := dec.Decode(&l.scts); err != nil {
		return err
	}
	return nil
}
