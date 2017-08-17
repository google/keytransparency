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


## Key Transparency Client

### Setup
1. Install [Go 1.7](https://golang.org/doc/install).
2. `go get -u github.com/google/keytransparency/cmd/keytransparency-client `
3. Get an [OAuth client ID](https://console.developers.google.com/apis/credentials) and download the generated JSON file to `client_secret.json`.

### Client operations

#### Publish a public key

  ```sh
  keytransparency-client authorized-keys --help 
  keytransparency-client authorized-keys add --generate --type=ecdsa --activate
  keytransparency-client post user@domain.com app1 --client-secret=client_secret.json --insecure -d 'dGVzdA==' #Base64
  ```

#### Get and verify a public key

  ```
  keytransparency-client get <email> <app> --insecure --verbose
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

#### Verify key history
  ```
  keytransparency-client history <email> --insecure
  Epoch |Timestamp                    |Profile
  4     |Mon Sep 12 22:23:54 UTC 2016 |keys:<key:"app1" value:"test" >
  ```


## Running the server

### Install 
1. [OpenSSL](https://www.openssl.org/community/binaries.html)
1. [Docker](https://docs.docker.com/engine/installation/) 
   - Docker Engine 1.13.0+ `docker version -f '{{.Server.APIVersion}}'`
   - Docker Compose 1.11.0+ `docker-compose --version`
1. `go get -u github.com/google/keytransparency/...`
1. `go get -u github.com/google/trillian/...`
1. `./scripts/prepare_server.sh -f` 

### Run
1. Start Trillian

  ```sh
$ docker-compose up -d trillian-map trillian-log
Creating keytransparency_db_1
Creating  keytransparency_trillian-map_1
Creating  keytransparency_trillian-log_1
  ```

2. Provision a log and a map 
```sh
source scripts/configure_trillian.sh && createLog && createMap
```

3. Run Key Transparency
- `docker-compose up -d`
- `docker-compose logs --tail=0 --follow`
- [https://localhost:8080/v1/users/foo@bar.com?app_id=app1](https://localhost:8080/v1/users/foo@bar.com?app_id=app1)
- [https://localhost:8080/v1/domain/info](https://localhost:8080/v1/domain/info)
- [Prometheus graphs](http://localhost:9090/graph)

