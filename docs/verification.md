# Key Transparency Verification

## Sender Verification

When looking up a recipient's public key in Key Transparency, clients must
complete the following verification steps to ensure that the key material
they are receiving is the same key material that the account owners and
auditors have verified.

Upon requesting the key material for an account, senders are provided with
the following data:

```json
{
  "vrf": "BMOmWsO0Bwj9Tk9l8czqH2jFYrmXGwM/gbHQIDXq3xaOoqrrZO7Z6R9pYONsj2nEHxckyHIH1o9mZXADatMelr4=",
  "vrf_proof": "lnDRwW6BCyv8K5AnbsTT9t50+x+WcyDigMGIuqplgAS1xQeJ9HvEm7ZRDEcCUGublzv2nu7cdwLyD51ePRTzjA==",
  "committed": {
    "key": "B4IhW09t4bYTkQZF1p7Rvw==",
    "data": "CgwKBGFwcDISBHRlc3QKDAoEYXBwMRIEdGVzdA=="
  },
  "leaf_proof": {
    "leaf_data": "CiD3g7UGE7qOyTPGnLsw9SmwCWMPzjPz65G0vv4cfVw99w==",
    "neighbors": ["", "/* 256 items */", ""]
  },
  "smh": {
    "map_head": {
      "realm": "example.com",
      "snapshot": "7573",
      "root": "3MQ3sfHl1wT6iCuVvRHFRqTN587J9Npr8rz4OzyB/iE=",
      "issue_time": "2016-09-01T21:06:09.515380163Z"
    },
    "signatures": {
      "61153815": {
        "hash_algorithm": "SHA256",
        "sig_algorithm": "ECDSA",
        "signature": "MEYCIQDDIAu0UgMFTCsCqvWA15uHzc43VBYa7sRMvmxDLRiS0AIhAPiWCDBLdJFiGmkUAlyqPWgMVobONB5a25xLQSSWZaGb"
      }
    }
  },
  "smh_sct": "AN8cLsEVAJRSR6lhaDJd3Fx5Wej3xtOI/AAuC70/dNdkAAABVueQO4sAAAQDAEYwRAIgI2teJpbbjXb8Xld8Jn3jy5yu4WYY6ddeB+vGsg1eqHkCIBRqnXEq8Owg1rVUGxb3Q52UZ2y6DxQ9HJ+ZYTAQW8RQ"
}
```


### Verification Steps


1.  Verify the cryptographic commitment to the public keys. The keys themselves
are contained in the `data` portion of the `committed` field. To verify
that the public keys match the commitment in the `leaf_data` of the Merkle
Tree, ensure that `leaf_data == Commit(email, committed.key, committed.data)`.

1.  Verify the user’s index in the Merkle Tree, which is determined by a SHA256
hash of the VRF value. Confirm that `VRF_Verify(pk, email, vrf, vrf_proof)`
succeeds.  The VRF ensures that the user’s email is protected, and the VRF
proof ensures that there is only one possible index for the user.

1.  Verify that the leaf data, when combined with the interior neighbor nodes
of the Merkle Tree matches the expected root in the signed map head (`smh`).
Use the index from the previous step to determine whether the neighbors nodes
are on the left or right.

1.  Verify that SMH is signed by the expected directory provider.
Use the provider’s public signing key to look up their signature in the
`signatures` map and verify that the signature valid over the ObjectHash of
`map_head`.

1.  Verify that the signed map head has been included in an append-only log
    1.  Verify the Signed Certificate Timestamp (SCT) signature, which
	represents a promise by the Certificate Transparency (CT) server to
	include the SMH in the log within 24 hrs.

    1.  If less than 24 hrs have passed, save the SCT for verification later.

    1.  If more than 24 hrs have passed, request the latest Signed Tree Head
	(STH) from CT and verify its signature.

    1.  Request a consistency proof from the previous STH to the new one. If
	this is the first time ever interacting with Key Transparency,
	automatically trust the first correctly signed STH.

    1.  Request an inclusion proof into the current STH for the SCT of the SMH.

## Account Audit

Account owners want to verify that the keys being held for them in the Key
Transparency server represent keys that they own and recognize. Account owners
perform the following steps to audit their accounts:

### Audit Steps

1.  Take on the role of a sender and request the current keys for oneself,
performing all the verification steps outlined above.

1.  For each snapshot since the last audit until the current snapshot:

    1.  Fetch the profile at that snapshot and verify using the steps above.

    1.  Identify all the public keys listed. If any are unrecognized, raise a
	warning.

Auditing in this form is simple and does not rely on 3rd parties but it is
expensive in terms of network time and bandwidth. An optimization on this
auditing approach using 3rd party auditors has been designed but
not-yet-implemented.
