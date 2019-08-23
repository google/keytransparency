package vrf

import (
	"crypto/elliptic"
	"crypto/sha256"
	"hash"
)

type VRF interface {
	// A VRF comes with a key generation algorithm that generates a public
	// VRF key PK and private VRF key SK.
	Generate() ([]byte, []byte) // SK, PK

	// The prover hashes an input alpha using the private VRF key SK.
	// Returns VRF hash output beta.
	// Hash is deterministic, in the sense that it always
	// produces the same output beta given a pair of inputs (SK, alpha).
	Hash(SK, alpha []byte) []byte // VRF hash output b

	// Proof returns proof pi that beta is the correct hash output.
	Prove(SK PrivateKey, alpha []byte) []byte // pi

	// ProofToHash allows anyone to deterministically obtain the VRF hash
	// output beta directly from the proof value pi.
	// Hash(SK, alpha) = ProofToHash(Prove(SK, alpha))
	ProofToHash(pi []byte) []byte // beta

	// The proof pi allows a Verifier holding the public key PK to verify
	// that beta is the correct VRF hash of input alpha under key PK.
	// Returns (true, beta = ProofToHash(pi)) if pi is valid, and false otherwise.
	Verify(PK, alpha, pi) bool

	ValidateKey(PK) bool
}
