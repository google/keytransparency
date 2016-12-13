# Key Transparency

[![Go Report Card](https://goreportcard.com/badge/github.com/google/key-transparency)](https://goreportcard.com/report/github.com/google/key-transparency)
[![GoDoc](https://godoc.org/github.com/google/key-transparency?status.svg)](https://godoc.org/github.com/google/key-transparency)

![Key Transparency Logo](docs/images/logo.png)


Key Transparency provides a lookup service for generic records and a public,
tamper-proof audit log of all record changes. While being publicly auditable,
individual records are only revealed in response to queries for specific IDs.

Key Transparency can be used as a public key discovery service to authenticate
users and provides a mechanism to keep the service accountable.  It can be used
by account owners to [reliably see](docs/verification.md) what keys have been
associated with their account, and it can be used by senders to see how long an
account has been active and stable before trusting it. 

* [Overview](docs/overview.md)
* [Design document](docs/design.md)
* [API](docs/http_apis.md)

Key Transparency is inspired by [CONIKS](https://eprint.iacr.org/2014/1004.pdf)
and [Certificate Transparency](https://www.certificate-transparency.org/).
It is a work-in-progress with the [following
milestones](https://github.com/google/key-transparency/milestones) under
development.


## Using the Key Transparency Client

1. Install [Go](https://golang.org/doc/install). 
Set `$GOPATH` variable to point to your Go workspace directory and add `$GOPATH/bin` to the `$PATH` variable.

2. Install prerequisites, Key Transparency client code, and sync all dependencies

  ```sh
  apt-get install build-essential libssl-dev
  go get -u github.com/kardianos/govendor
  go get -u github.com/google/key-transparency/cmd/...
  cd $GOPATH/src/github.com/google/key-transparency
  govendor sync
  ```

3. Get an [OAuth client ID](https://console.developers.google.com/apis/credentials) and download the generated JSON file.

4. Run the client setup tool

  ```sh
  ./scripts/prepare_client.sh
  ```

5. Set/Update a user's keys. 

  ```sh
  ./key-transparency-client post <email> -d '{"app1": "dGVzdA=="}' --config=./.key-transparency.yaml
  {Keys:map[app1:[116 101 115 116]}

  ```
  Key material is base64 encoded.

6. Fetch and verify a user's keys:

  ```
  ./key-transparency-client get <email> --config=.key-transparency.yaml --verbose
  ✓ Commitment verified.
  ✓ VRF verified.
  ✓ Sparse tree proof verified.
  ✓ Signed Map Head signature verified.
  CT ✓ STH signature verified.
  CT ✓ Consistency proof verified.
  CT   New trusted STH: 2016-09-12 15:31:19.547 -0700 PDT
  CT ✓ SCT signature verified. Saving SCT for future inclusion proof verification.
  ✓ Signed Map Head CT inclusion proof verified.
  keys:<key:"app1" value:"test" >
  ```

  ```
  ./key-transparency-client history <email> --config=.key-transparency.yaml
  Epoch |Timestamp                    |Profile
  4     |Mon Sep 12 22:23:54 UTC 2016 |keys:<key:"app1" value:"test" >
  ```


## Running a Key Transparency Cluster

1. Install [etcd v3.0.0](https://github.com/coreos/etcd/releases/tag/v3.0.0).

2. Install Key Transparency

  ```sh
  apt-get install build-essential libssl-dev
  go get -u github.com/mattn/goreman
  go get -u github.com/kardianos/govendor
  go get -u github.com/google/key-transparency/...
  cd $GOPATH/src/github.com/google/key-transparency
  govendor sync
  ```

4. Get a [service account key](https://console.developers.google.com/apis/credentials) and download the generated JSON file.

  The service account key is used to verify client OAuth tokens.

5. Run server setup 

  ```sh
  ./scripts/prepare_server.sh
  ```

  The tool will build the server binaries, generate keys, and configure the server.
  Clients will need the following public keys in order to verify server responses:

  - `genfiles/vrf-pubkey.pem`
  - `genfiles/server.crt`
  - `genfile/p256-pubkey.pem`

6. Run

  ```sh
  goreman start
  ```
