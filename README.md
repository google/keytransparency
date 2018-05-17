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
1. Install [Go 1.10](https://golang.org/doc/install).
2. `go get -u github.com/google/keytransparency/cmd/keytransparency-client `

### Client operations

#### Generate a private key

  ```sh
  keytransparency-client authorized-keys create-keyset -p password
  keytransparency-client authorized-keys list-keyset -p password
  ```

#### Publish the public key
1. Get an [OAuth client ID](https://console.developers.google.com/apis/credentials) and download the generated JSON file to `client_secret.json`.

  ```sh
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
1. Run Key Transparency

  ```sh
$ docker-compose up -d
Creating keytransparency_db_1 ...         done
Creating keytransparency_map_server_1 ... done
Creating keytransparency_log_server_1 ... done
Creating keytransparency_log_server_1 ... done
Creating keytransparency_server_1 ...     done
Creating keytransparency_sequencer_1 ...  done
Creating keytransparency_monitor_1 ...    done
Creating keytransparency_init_1 ...       done
Creating keytransparency_prometheus_1 ... done
Creating keytransparency_monitor_1 ...    done
  ```

2. Watch it Run
- `docker-compose logs --tail=0 --follow`
- [Proof for app1/foo@bar.com](https://35.224.99.110:8080/v1/domains/default/apps/appID/users/foo@bar.com)
- [Server configuration info](https://35.224.99.110:8080/v1/domains/default)
- [Prometheus graphs](http://35.184.145.242:9090/alerts)

## Development and Testing
Key Transparency and its [Trillian](https://github.com/google/trillian) backend
use a [MySQL database](https://github.com/google/trillian/blob/master/README.md#mysql-setup),
which must be setup in order for the Key Transparency tests to work.


### Directory structure

The directory structure of Key Transparency is as follows:

* [**cmd**](cmd): binaries
    * [**keytransparency-client**](cmd/keytransparency-client): Key Transparency CLI client.
    * [keytransparency-sequencer](cmd/keytransparency-sequencer): Key Transparency backend.
    * [keytransparency-server](cmd/keytransparency-sequencer): Key Transparency frontend.
* [**core**](core): main library source code. Core libraries do not import [impl](impl).
    * [adminserver](core/adminserver): private api for creating new domains and apps.
    * [**api**](core/api): gRPC API definitions.
    * [**crypto**](core/crypto): verifiable random function and commitment implementations.
    * [domain](core/domain): interface for retrieving domain info from storage.
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

