# Key Transparency

[![GoDoc](https://godoc.org/github.com/google/keytransparency?status.svg)](https://godoc.org/github.com/google/keytransparency)
[![Build Status](https://travis-ci.com/google/keytransparency.svg?branch=master)](https://travis-ci.com/google/keytransparency)
[![Go Report Card](https://goreportcard.com/badge/github.com/google/keytransparency)](https://goreportcard.com/report/github.com/google/keytransparency)
[![codecov](https://codecov.io/gh/google/keytransparency/branch/master/graph/badge.svg)](https://codecov.io/gh/google/keytransparency)

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
* [API](docs/api.md)

Key Transparency is inspired by [CONIKS](https://eprint.iacr.org/2014/1004.pdf)
and [Certificate Transparency](https://www.certificate-transparency.org/).
It is a work-in-progress with the [following
milestones](https://github.com/google/keytransparency/milestones) under
development.


## Key Transparency Client

### Setup
1. Install [Go 1.10](https://golang.org/doc/install).
2. `go get -u github.com/google/keytransparency/cmd/keytransparency-client `

### Client operations

#### Generate a private key

  ```sh
  PASSWORD=[[YOUR-KEYSET-PASSWORD]]
  keytransparency-client authorized-keys create-keyset --password=${PASSWORD}
  keytransparency-client authorized-keys list-keyset --password=${PASSWORD}
  ```
The `create-keyset` command will create a `.keyset` file in the user's working directory.
To specify custom directory use `--keyset-file` or `-k` shortcut.

NB A default for the Key Transparency server URL is being used here. The default value is "35.202.56.9:443". The flag `--kt-url` may be used to specify the URL of Key Transparency server explicitly.


#### Publish the public key
1. Get an [OAuth client ID](https://console.developers.google.com/apis/credentials) and download the generated JSON file to `client_secret.json`.

  ```sh
  keytransparency-client post user@domain.com \
  --client-secret=client_secret.json \
  --insecure \
  --password=${PASSWORD} \
  --data='dGVzdA==' #Base64
  ```

#### Get and verify a public key

  ```
  keytransparency-client get <email> --insecure --verbose
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
  Revision |Timestamp                    |Profile
  4        |Mon Sep 12 22:23:54 UTC 2016 |keys:<key:"app1" value:"test" >
  ```

#### Checks
- [Proof for foo@bar.com](https://35.202.56.9/v1/directories/default/users/foo@bar.com)
- [Server configuration info](https://35.202.56.9/v1/directories/default)

## Running the server

1. [OpenSSL](https://www.openssl.org/community/binaries.html)
1. [Docker](https://docs.docker.com/engine/installation/)
   - Docker Engine 1.13.0+ `docker version -f '{{.Server.APIVersion}}'`
   - Docker Compose 1.11.0+ `docker-compose --version`

```sh
go get -u github.com/google/keytransparency/...
go get -u github.com/google/trillian/...
cd $(go env GOPATH)/src/github.com/google/keytransparency
./scripts/prepare_server.sh -f
docker-compose up -f docker-compose.yml docker-compose.prod.yml
```

2. Watch it Run
- [Proof for foo@bar.com](https://localhost/v1/directories/default/users/foo@bar.com)
- [Server configuration info](https://localhost/v1/directories/default)

## Development and Testing
Key Transparency and its [Trillian](https://github.com/google/trillian) backend
use a [MySQL database](https://github.com/google/trillian/blob/master/README.md#mysql-setup),
which must be setup in order for the Key Transparency tests to work.

`docker-compose up -d db` will launch the database in the background.

### Directory structure

The directory structure of Key Transparency is as follows:

* [**cmd**](cmd): binaries
    * [**keytransparency-client**](cmd/keytransparency-client): Key Transparency CLI client.
    * [keytransparency-sequencer](cmd/keytransparency-sequencer): Key Transparency backend.
    * [keytransparency-server](cmd/keytransparency-sequencer): Key Transparency frontend.
* [**core**](core): main library source code. Core libraries do not import [impl](impl).
    * [adminserver](core/adminserver): private api for creating new directories.
    * [**api**](core/api): gRPC API definitions.
    * [**crypto**](core/crypto): verifiable random function and commitment implementations.
    * [directory](core/directory): interface for retrieving directory info from storage.
    * [keyserver](core/keyserver): keyserver implementation.
    * [**mutator**](core/mutator): "smart contract" implementation.
    * [sequencer](core/sequencer): mutation executor.
* [**deploy**](deploy): deployment configs:
    * [docker](deploy/docker): init helper.
    * [**kubernetes**](deploy/kubernetes): kube deploy configs.
    * [prometheus](deploy/prometheus): monitoring docker module.
* [**docs**](docs): documentation.
* [**impl**](impl): environment specific modules:
    * [**authentication**](impl/authentication): authentication policy grpc interceptor.
    * [**authorization**](impl/authorization): OAuth and fake auth grpc interceptor.
    * [integration](impl/integration): environment specific integration tests.
    * [**sql**](impl/sql): mysql implementations of storage modules.
* [**scripts**](scripts): scripts
    * [**deploy**](scripts/deploy.sh): deploy to Google Compute Engine.


## Support

- [Mailing list](https://groups.google.com/forum/#!forum/keytransparency).

