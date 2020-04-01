package vrf

type VRF interface {
	Params() *ECVRFParams

	// Prove returns proof pi that beta is the correct hash output.
	Prove(sk *PrivateKey, alpha []byte) (pi []byte)

	// ProofToHash allows anyone to deterministically obtain the VRF hash
	// output beta directly from the proof value pi.
	//
	// ProofToHash should be run only on pi that is known to have been produced by Prove
	// Clients attempting to verify untrusted inputs should use Verify.
	ProofToHash(pi []byte) (beta []byte, err error)

	// Verify that beta is the correct VRF hash of alpha using PublicKey Y.
	Verify(Y *PublicKey, pi, alpha []byte) (beta []byte, err error)
}
