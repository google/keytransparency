# Key Transparency HTTP APIs

## Introduction

This document describes the Key Transparency Server HTTP APIs.
The core gRPC APIs are exposed over HTTP via a
[gRPC reverse proxy](https://github.com/grpc-ecosystem/grpc-gateway).

## Index
<table>
<tr><td>Path</td><td>Method</td><td>Summary</td></tr>
<tr><td>`/v1/users/{user_id}`</td><td>GET</td><td>GetUser returns a user's entry in the Merkle Tree.</td></tr>
<tr><td>`/v1/users/{user_id}`</td><td>PUT</td><td>UpdateEntry submits a SignedEntryUpdate.</td></tr>
<tr><td>`/v1/users/{user_id}/history`</td><td>GET</td><td>ListEntryHistory returns a list of historic GetUser values.</td></tr>
</table>

### `GET /v1/users/{user_id}`
Returns a user's set of public keys, along with various cryptographic proofs.

`curl https://<host>/v1/users/user_id`

#### Parameters
<table>
<tr><td>Parameter</td><td>Required</td><td>Type</td><td>Description</td></tr>
<tr><td>user_id</td><td>•</td><td>String</td><td>Email address</td></tr>
</table>

#### Response

Empty proof for an entry that is not found:
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
      "revision": "7573",
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

Proof for an entry that exists:
```json
TODO
```

### `PUT /v1/users/{user_id}`

```sh
curl
-X PUT
-H "Authorization: OAuth <ACCESS_TOKEN>"
https://<host>/v1/users/user_id
-d "<json below>"
```

#### Request
```json
{
  "entry_update": {
    "update": {
      "key_value": {
        "//   key: VRF Index obtained via a GET operation"
	"key": "BtVQb1P7Em+lTUKEH3c5lw==",
        "//   value: ProtoSerialize(Entry{ "
        "//      commitment: HMAC(committed.key, committed.data),"
        "//      authorized_keys: authorized_keys, "
        "//    })"
        "value": "CiAhWorzTMne08bTtf9tfha0ouSWD7hb2z8GLNwwyXVgyBIiCiAnVXbqdmof99bSQH5jieVmdAd8Ooss0gL8OPwF6DBb5A==",
      },
      "// signatures is a map from key ids to signatures on key_value"
      "signatures": {"k": "1234", "v": "SJT3BgccSMEbSR0ZqjLHYhcXe+P04S00g1Kmktj4z8I="},
      "// ObjectHash of previous entry."
      "previous": "SJT3BgccSMEbSR0ZqjLHYhcXe+P04S00g1Kmktj4z8I="
    },
    "committed": {
      "// key is a random 16 byte value"
      "key": "BtVQb1P7Em+lTUKEH3c5lw==",
      "// data = ProtoSerialize(Profile(your key data))"
      "data": "CgwKBGFwcDESBHRlc3QKDAoEYXBwMhIEdGVzdA==",
    },
  }
}
```


#### Response

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
      "revision": "7573",
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

### `GET /v1/user/{user_id}/history`

#### Request
```json
{
  "start": "5030",
  "page_size": 1
}
```

#### Response
```json
{
  "values": [ "/* Objects from GetUser */" ],
  "next_start": "5031"
}
```
