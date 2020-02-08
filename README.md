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
1. Install [Go 1.13](https://golang.org/doc/install).
3. `GO111MODULE=on go get github.com/google/keytransparency/cmd/keytransparency-client`

### Client operations


## View the Server's Public Keys for a Directory 
The Key Transparency server publishes a separate set of public keys for each directory that it hosts.

Within a directory the server uses the following public keys to sign its responses:
1. `log.public_key` signs the top-most merkle tree root, covering the ordered list of map roots.
2. `map.public_key` signs each snapshot of the key-value database in the form of a sparse merkle tree.
3. `vrf.der` signs outputs of the [Verifiable Random Function](https://en.wikipedia.org/wiki/Verifiable_random_function)
    which obscures the key values in the key-value database.

A directory's keys default can be retrieved over HTTPS/JSON with curl
or over gRPC with [grpcurl](https://github.com/fullstorydev/grpcurl).
```sh
$ curl -s https://sandbox.keytransparency.dev/v1/directories/default | json_pp
$ grpcurl -d '{"directory_id": "default"}' sandbox.keytransparency.dev:443 google.keytransparency.v1.KeyTransparency/GetDirectory
```

<details>
  <summary>Show output</summary>

```sh
{
   "directory_id" : "default",
   "log" : {
      "hash_algorithm" : "SHA256",
      "hash_strategy" : "RFC6962_SHA256",
      "public_key" : {
         "der" : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXPi4Ut3cRY3OCXWvcSnE/sk6tbDEgBeZapfEy/BIKfsMbj3hPLG+WEjzh1IP2TDirc9GpQ+r9HVGR81KqRpbjw=="
      },
      "signature_algorithm" : "ECDSA",
      "tree_id" : "4565568921879890247",
      "tree_type" : "PREORDERED_LOG"
   },
   "map" : {
      "hash_algorithm" : "SHA256",
      "hash_strategy" : "CONIKS_SHA256",
      "public_key" : {
         "der" : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgX6ITeFrqLmclqH+3XVhbaEeJO37vy1dZYRFxpKScERdeeu3XRirJszc5KJgaZs0LdvJqOccfNc2gJfInLGIuA=="
      },
      "signature_algorithm" : "ECDSA",
      "tree_id" : "5601540825264769688",
      "tree_type" : "MAP"
   },
   "max_interval" : "60s",
   "min_interval" : "1s",
   "vrf" : {
      "der" : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvuqCkY9rM/jq/8hAoQn2PClvlNvVeV0MSUqzc67q6W+MzY/YZKmPLY5t/n/VUEqeSgwU+/sXgER3trsL6nZu+A=="
   }
}
```
</details>

#### [Optional] Generate a key signing key
Key Transparency supports key signing keys for the purpose of making the provenance of public keys explicit.

This feature can be deployed in a variety of configurations:
1. Only the service provider signs updates.
   This mode most clearly models most applications today that support account-reset.
   The service provider authenticates the user using SMS, OAuth, Email, or some other mechanism and then updates the key directory.
2. The service provider and, optionially, the user sign updates.
   This mode allows relyinig parties to distinguish between account reset
   events and new devices that were added by the user from other devices.
3. The reset providers, and optionally, the user sign updates.
   This mode removes the power of the service provder to unilaterally update a
   user's account, while preserving the ability for users to recover their accounts.
4. Require user signed updates after account setup.
   This mode requires the user maintain access to their key signing keys in
   perpetuity or risk loosing access to their account.

If supported by the service provider, each user can select the mode most
appropriate for their own account by modifying the set of key signing keys in `authorized_keys`.

The sandbox server has been setup in mode 4.
  ```sh
  PASSWORD=[[YOUR-KEYSET-PASSWORD]]
  keytransparency-client authorized-keys create-keyset --password=${PASSWORD}
  keytransparency-client authorized-keys list-keyset --password=${PASSWORD}
  ```
The `create-keyset` command will create a `.keyset` file in the user's working directory.
To specify custom directory use `--keyset-file` or `-k` shortcut.

#### Publish the public key
1. Get an [OAuth client ID](https://console.developers.google.com/apis/credentials) and download the generated JSON file to `client_secret.json`.

  ```sh
  keytransparency-client post user@domain.com \
  --client-secret=client_secret.json \
  --kt-url sandbox.keytransparency.dev \
  --password=${PASSWORD} \
  --data='dGVzdA==' #Base64
  ```

#### Get and verify a public key

  ```
  keytransparency-client get <email> --kt-url sandbox.keytransparency.dev:443 --verbose
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
  keytransparency-client history user@domain.com --kt-url sandbox.keytransparency.dev:443
  Revision |Timestamp                    |Profile
  4        |Mon Sep 12 22:23:54 UTC 2016 |keys:<key:"app1" value:"test" >
  ```

#### Checks
- [Proof for foo@bar.com](https://sandbox.keytransparency.dev/v1/directories/default/users/foo@bar.com)
- [Server configuration info](https://sandbox.keytransparency.dev/v1/directories/default)

## Running the server

1. [OpenSSL](https://www.openssl.org/community/binaries.html)
1. [Docker](https://docs.docker.com/engine/installation/)
   - Docker Engine 1.17.6+ `docker version -f '{{.Server.APIVersion}}'`
   - Docker Compose 1.11.0+ `docker-compose --version`

```sh
go get github.com/google/keytransparency/...
go get github.com/google/trillian/...
cd $(go env GOPATH)/src/github.com/google/keytransparency
./scripts/prepare_server.sh -f
docker-compose -f docker-compose.yml docker-compose.prod.yml up
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

