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

1. Install the [Go Programming Language](https://golang.org/doc/install). Set `$GOPATH` variable to point to your Go workspace directory and add `$GOPATH/bin` to the `$PATH` variable.

2. Install prerequisites, Key Transparency client code, and sycn all dependencies

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
  $GOPATH/src/github.com/google/key-transparency/scripts/prepare_client.sh
  ```
  
  This tool configures the following options:
  * VRF verification key: use the default value if you want to connect to the experimental Key Transparency server or enter the path of your own server's VRF verification key.
  * gRPC/HTTPs certificate: use the default to connect the experimental server or your own server's certificate.
  * Signature verification key: use the default to connect the experimental server or your own server's key.
  * Domain name: use `example.com` if you want to use the experimental Key Transparency server or you are running your own server without a domain name.
  * URL and port: use `104.199.112.76:5001` (which is the default value) if you want to connect to the experimental Key Transparency server, or your own server information otherwise.

5. Set/Update a user's keys. Key material is represented in base64 encoding, e.g., `app1` value.

  ```sh
  ./key-transparency-client post <email> -d '{"app1": "dGVzdA=="}' --config=./.key-transparency.yaml
  {Keys:map[app1:[116 101 115 116]}

  ```

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

Key Transparency cluster can run in two modes:

* Local: the cluster runs on the local machine containing one frontend, one backend, and three etcd instances.
* Remote: the cluster runs on three separate machines: two frontends and one backend. Each machine runs its own etcd instance.

The following steps configures both local and remote Key Transparency clusters. In case of remote mode, these steps should be followed on each of your cluster machines.

1. Install the [Go Programming Language](https://golang.org/doc/install). Set `$GOPATH` variable to point to your Go workspace directory and add `$GOPATH/bin` to the `$PATH` variable.

2. Install [etcd v3.0.0](https://github.com/coreos/etcd/releases/tag/v3.0.0) binaries.

3. Install prerequisites, Key Transparency code, and sycn all dependencies

  ```sh
  apt-get install build-essential libssl-dev
  go get -u github.com/mattn/goreman
  go get -u github.com/kardianos/govendor
  go get -u github.com/google/key-transparency/...
  cd $GOPATH/src/github.com/google/key-transparency
  govendor sync
  ```

4. Get a [service account key](https://console.developers.google.com/apis/credentials) and download the generated JSON file.

5. Run the server setup tool

  ```sh
  $GOPATH/src/github.com/google/key-transparency/scripts/prepare_server.sh
  ```

  This tool configures the following options (not all options are configured in both local and remote mode):
  * Whether you are configuring a frontend or a backend instance.
  * Database engine. Key Transparency currently supports SQlite and MySQL.
  * MySQL Data Source Name (DSN), if MySQL is selected as a database engine.
  * Frontend and backend IP addresses. These are used to configure the etcd cluster.
  * Application credentials file which is the service account key JSON file downloaded in the previous step.
  * The IP address on which the frontend is listening.
  * Frontend domain name for frontend certificate creation.
  * Frontend public IP address to be added to the certificate SAN field in case your frontend does not have a domain name.

  The tool will build the binaries, generated the necessary cryptographic material in `genfiles`, and setup the configuration file. Make sure to disseminate `genfiles/vrf-pubkey.pem`, `genfiles/server.crt`, and `genfile/p256-pubkey.pem` to your clients.

6. Run

  ```sh
  goreman start
  ```

## Projects Using Key Transparency
* [Google End-To-End](https://github.com/google/end-to-end).
