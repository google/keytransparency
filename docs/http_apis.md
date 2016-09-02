# Key Transparency HTTP APIs

## Introduction

This document describes the Key Transparency Server HTTP APIs.
The core [gRPC APIs](api_gen.md) are exposed over HTTP via a
[gRPC reverse proxy](https://github.com/grpc-ecosystem/grpc-gateway).

## Index
<table>
<tr><td>Path</td><td>Method</td><td>Summary</td></tr>
<tr><td>/v1/users/{user_id}</td><td>GET</td><td>GetEntry returns a user's entry in the Merkle Tree.</td></tr>
<tr><td>/v1/users/{user_id}</td><td>PUT</td><td>UpdateEntry submits a SignedEntryUpdate.</td></tr>
<tr><td>/v1/users/{user_id}/history</td><td>GET</td><td>ListEntryHistory returns a list of historic GetEntry values.</td></tr>
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
      "epoch": "7573",
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
-X POST
-H "Authorization: OAuth <ACCESS_TOKEN>"
https://<host>/v1/users/user_id
-d "<json below>"
```

#### Request
```json
{
  "entry_update": {
    "update": {
      "// serialized(KeyValue{email: serialized(Entry{ commitment }})"
      "key_value": "CiAhWorzTMne08bTtf9tfha0ouSWD7hb2z8GLNwwyXVgyBIiCiAnVXbqdmof99bSQH5jieVmdAd8Ooss0gL8OPwF6DBb5A==",
      "previous": "SJT3BgccSMEbSR0ZqjLHYhcXe+P04S00g1Kmktj4z8I="
    },
    "committed": {
      "key": "BtVQb1P7Em+lTUKEH3c5lw==",
      "data": "CgwKBGFwcDESBHRlc3QKDAoEYXBwMhIEdGVzdA=="
    }
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
      "epoch": "7573",
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
