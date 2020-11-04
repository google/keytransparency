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
users and provides a mechanism to keep the service accountable.  

Key Transparency empowers account owners to [reliably see](docs/verification.md) what public keys have been
associated with their account, and it can be used by senders to see how long an
account has been active and stable before trusting it.

Key Transparency can add [verifiable](docs/verification.md) and user-friendly auditing to any [scenario](docs/scenarios.md) that involves 
authenticating users with public keys, including [Universal Second Factor Security Keys](https://en.wikipedia.org/wiki/Universal_2nd_Factor) and end-to-end encryption.

* [Overview](docs/overview.md)
* [Design document](docs/design.md)
* [API](docs/api.md)

### Project Status
Key Transparency is a work-in-progress with the [following milestones](https://github.com/google/keytransparency/milestones) under development.

## Key Transparency Client

### Setup
1. Install [Go 1.13](https://golang.org/doc/install).
2. `GO111MODULE=on go get github.com/google/keytransparency/cmd/keytransparency-client`

### Client operations

## View a Directory's Public Keys
The Key Transparency server publishes a separate set of public keys for each directory that it hosts.
By hosting multiple directories, a single domain can host directories for multiple apps or customers.
A standardized pattern for discovering domains and directories is a TODO in issue #389.

Within a directory the server uses the following public keys to sign its responses:
1. `log.public_key` signs the top-most Merkle tree root, covering the ordered list of map roots.
2. `map.public_key` signs each snapshot of the key-value database in the form of a sparse Merkle tree.
3. `vrf.der` signs outputs of the [Verifiable Random Function](https://en.wikipedia.org/wiki/Verifiable_random_function)
    which obscures the key values in the key-value database.

A directory's public keys can be retrieved over HTTPS/JSON with curl
or over gRPC with [grpcurl](https://github.com/fullstorydev/grpcurl).
The sandboxserver has been initialized with a domain named `default`.
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

#### Generate Update Signing Keys
Every update to a user record in key transparency must be signed by an `authorized-key`.

Update signatures are saved in the Merkle tree data structure, producing a record of *who* made each change to a user's
account, allowing products to distinguish between changes signed by a user key, the provider's key, or a reset-provider's key.

Each account has an updatable policy that lists the current set of authorized public keys that are allowed to make updates to the user's record.

To create an initial set of update signing keys, run the `authorized-keys create-keyset` command.
Keys will be saved in a `.keyset` file in the current working directory.
```sh
$ PASSWORD=[[YOUR-KEYSET-PASSWORD]]
$ keytransparency-client authorized-keys create-keyset --password=${PASSWORD}
```
<details>
  <summary>Show output</summary>

```sh
$ PASSWORD=[[YOUR-KEYSET-PASSWORD]]
$ keytransparency-client authorized-keys create-keyset --password=${PASSWORD}
$ keytransparency-client authorized-keys list-keyset --password=${PASSWORD}
My Authorized Keys:
primary_key_id:17445529 key_info:<type_url:"type.googleapis.com/google.crypto.tink.EcdsaPrivateKey" status:ENABLED key_id:17445529 output_prefix_type:TINK >
```
</details>

#### Publish the public key
Any number of protocols may be used to prove to the server that a client owns a userID.
The sandbox server supports a fake authentication string and [OAuth](https://console.developers.google.com/apis/credentials).

Create or fetch the public key for your specific application.
  ```sh
   openssl genpkey -algorithm X25519 -out xkey.pem
   openssl pkey -in xkey.pem -pubout
   -----BEGIN PUBLIC KEY-----
   MCowBQYDK2VuAyEAtCAsIMDyVUUooA5yhgRefcEr7edVOmyNCUaN1LCYl3s=
   -----END PUBLIC KEY-----
  ```

  ```sh
  keytransparency-client post user@domain.com \
  --kt-url sandbox.keytransparency.dev:443 \
  --fake-auth-userid user@domain.com \
  --password=${PASSWORD} \
  --verbose \
  --logtostderr \
  --data='MCowBQYDK2VuAyEAtCAsIMDyVUUooA5yhgRefcEr7edVOmyNCUaN1LCYl3s=' #Your public key in base64
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

## Running the server locally with Docker Compose

Prerequisites
- [GoLang](https://golang.org/doc/install)
- [OpenSSL](https://www.openssl.org/community/binaries.html)
- [Docker](https://docs.docker.com/engine/installation/)
   - Docker Engine 1.17.6+ `docker version -f '{{.Server.APIVersion}}'`
   - Docker Compose 1.11.0+ `docker-compose --version`

### Deploy the KeyTransparency service

1. Run the deployment script
   ```sh
   # Download the latest version of keytransparency
   git clone https://github.com/google/keytransparency.git
   cd keytransparency

   # Run the deployment script for local environment
   ./scripts/deploy_local.sh deploy
   ```

2. Check Docker's running containers
   ```sh
   docker container ls
   ```
   You should see 8 new running containers:
   - gcr.io/key-transparency/keytransparency-monitor
   - gcr.io/key-transparency/keytransparency-sequencer
   - gcr.io/trillian-opensource-ci/map_server
   - gcr.io/trillian-opensource-ci/log_signer
   - gcr.io/trillian-opensource-ci/log_server
   - gcr.io/key-transparency/keytransparency-server
   - gcr.io/trillian-opensource-ci/db_server
   - prom/prometheus

3. Watch it Run
- [Proof for foo@bar.com](https://localhost/v1/directories/default/users/foo@bar.com)
- [Server configuration info](https://localhost/v1/directories/default)


### Terminate the KeyTransparency service

The script will remove all the containers and their networks.
```sh
# Run the script to undeploy
./scripts/deploy_local.sh undeploy
```

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
    * [adminserver](core/adminserver): private API for creating new directories.
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
    * [**mysql**](impl/mysql): mysql implementations of storage modules.
* [**scripts**](scripts): scripts
    * [**deploy**](scripts/deploy.sh): deploy to Google Compute Engine.


## Support

- [Mailing list](https://groups.google.com/forum/#!forum/keytransparency).

## Acknowledgements

Key Transparency would not have been possible without a whole host of collaborators including researchers, interns, and [open source contributors](https://github.com/google/keytransparency/graphs/contributors).

Key Transparency was inspired by [CONIKS](https://eprint.iacr.org/2014/1004.pdf) and [Certificate Transparency](https://www.certificate-transparency.org/).

## Related

* [Google Security Blog Post](https://security.googleblog.com/2017/01/security-through-transparency.html)
* [CONIKS Project](https://coniks.cs.princeton.edu/)
* [Why Making Johnny's Key Management Transparent is So Challenging](https://freedom-to-tinker.com/2016/03/31/why-making-johnnys-key-management-transparent-is-so-challenging/)
* [Google Launches Key Transparency While a Trade-Off in WhatsApp Is Called a Backdoor](https://www.eff.org/deeplinks/2017/01/google-launches-key-transparency-while-tradeoff-whatsapp-called-backdoor)
* [On Ghost Users and Messaging Backdoors](https://blog.cryptographyengineering.com/2018/12/17/on-ghost-users-and-messaging-backdoors/)
* [Verifiable Random Functions](https://www.cs.bu.edu/~goldbe/projects/vrf)
* [Message Layer Security](https://tools.ietf.org/html/draft-ietf-mls-architecture)
* [OpenPGP Email Summit 2019](https://wiki.gnupg.org/OpenPGPEmailSummit201910Notes#Workshop:_Key_Transparency)
