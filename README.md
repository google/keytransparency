# Key Transparency

[![Build Status](https://travis-ci.org/google/keytransparency.svg?branch=master)](https://travis-ci.org/google/keytransparency)
[![Go Report Card](https://goreportcard.com/badge/github.com/google/keytransparency)](https://goreportcard.com/report/github.com/google/keytransparency)
[![GoDoc](https://godoc.org/github.com/google/keytransparency?status.svg)](https://godoc.org/github.com/google/keytransparency)

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
milestones](https://github.com/google/keytransparency/milestones) under
development.


## Using the Key Transparency Client

1. Install [Go](https://golang.org/doc/install) 1.7.
Set `$GOPATH` variable to point to your Go workspace directory and add `$GOPATH/bin` to the `$PATH` variable.

2. Install prerequisites, Key Transparency client code, and sync all dependencies

  ```sh
  go get -u github.com/google/keytransparency/cmd/...
  ```

3. Get an [OAuth client ID](https://console.developers.google.com/apis/credentials) and download the generated JSON file.

4. Run the client setup tool

  ```sh
  ./scripts/prepare_client.sh
  ```

5. Set/Update a user's keys. 

  ```sh
  ./keytransparency-client authorized-keys add --generate --type=ecdsa --activate
  ./keytransparency-client post user@domain.com app1 -d 'dGVzdA==' --config=./.keytransparency.yaml
  ```
  Key material is base64 encoded, e.g., 'dGVzdA==' is 'test' encoded.

  Note: Use `./keytransparency-client authorized-keys --help` for more information about authorized key managements.

6. Fetch and verify a user's keys:

  ```
  ./keytransparency-client get <email> --config=.keytransparency.yaml --verbose
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
  ./keytransparency-client history <email> --config=.keytransparency.yaml
  Epoch |Timestamp                    |Profile
  4     |Mon Sep 12 22:23:54 UTC 2016 |keys:<key:"app1" value:"test" >
  ```


## Running a Key Transparency Cluster

1. Install 
- [Etcd v3.1.3](https://github.com/coreos/etcd/releases/tag/v3.1.3).
- [OpenSSL](https://www.openssl.org/community/binaries.html)
- [Docker](https://docs.docker.com/engine/installation/) 
  - Docker Engine 1.13.0+ `docker version -f '{{.Server.APIVersion}}'`
  - Docker Compose 1.11.0+ `docker-compose --version`

2. Install Key Transparency

  ```sh
  go get -u github.com/google/keytransparency/...
  go get -u github.com/google/trillian/...
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

6. Run the trillian-map server 

  ```sh
docker-compose up -d trillian-map
  ```

7. Provision a log and a map 
```sh
MAP_IP=`docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' keytransparency_trillian-map_1`
go run $GOPATH/src/github.com/google/trillian/cmd/createtree/main.go --admin_server=$MAP_IP:8090 --pem_key_path=testdata/log-rpc-server.privkey.pem --pem_key_password="towel" --signature_algorithm=ECDSA --tree_type=LOG
go run $GOPATH/src/github.com/google/trillian/cmd/createtree/main.go --admin_server=$MAP_IP:8090 --pem_key_path=testdata/log-rpc-server.privkey.pem --pem_key_password="towel" --signature_algorithm=ECDSA --hash_strategy=TEST_MAP_HASHER --tree_type=MAP
```

Set the `LOG_ID` and `MAP_ID` environment variables in `docker-compose.yml` with the output
of the respective commands.

8. Launch the rest of the cluster and observe.
- `docker-compose up -d`
- `docker-compose logs --tail=0 --follow`
- [https://localhost:8080/v1/users/foo@bar.com](https://localhost:8080/v1/users/foo@bar.com)

