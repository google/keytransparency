# Key Transparency
Key Transparency is a distributed implementation of
[CONIKS](https://eprint.iacr.org/2014/1004.pdf), written in Go.

## Installing Key Transparency

1. Install the [Go Programming Language](https://golang.org/doc/install) and set your `$GOPATH` variable to point to your Go workspace directory.

2. Ensure that you have `gcc` and `openssl` commands installed and operational. On an Ubuntu machine, you can get both by running the following command:

  ```sh
  apt-get install build-essential libssl-dev
  ```

3. Install [ProtocolBuffers](https://github.com/golang/protobuf#installation) 3.0 or later.

4. Ensure `$GOPATH/bin` is in your `$PATH:` and `/usr/local/lib` is in your `$LD_LIBRARY_PATH`.

   ```sh
   export PATH=$PATH:$GOPATH/bin
   export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
   ```

5. Install the code and its prerequisites

  ```sh
  go get -u github.com/mattn/goreman
  go get -u github.com/coreos/etcd
  go get -u github.com/google/key-transparency/cmd/...
  ```

## Running a Key Transparency Cluster Locally
The following steps run a Key Transparency cluster on your local machine.

1. Generate test keys. In Key Transparency root directory, run:

  ```sh
  make local -C testdata
  ```

2. Get [Application Default Credentials](https://developers.google.com/identity/protocols/application-default-credentials)

  Use this [wizard](https://console.developers.google.com/start/api?id=e2ekeys)
  and set ```GOOGLE_APPLICATION_CREDENTIALS``` environment variable in
  [.env](.env) to point to the credentials file.

3. Download and run an XJSON [Certificate Transparency](https://github.com/google/certificate-transparency) Server.

  Set the `CTLOG` variable to the CT server URL in the [.env](.env) file.

4. Run

  ```sh
  goreman start
  ```

## Running a Key Transparency Cluster on Google Cloud
The following steps run a Key Transparency cluster on a Google cloud instance.

1. Add the public IP address of your Google cloud instance to the end of `testdata/openssl.cnf`.

  ```sh
  ...
  keyUsage         = nonRepudiation, digitalSignature, keyEncipherment
  subjectAltName   = @alt_names

  [alt_names]
  DNS.1 = localhost
  IP.1 = 127.0.0.1
  IP.2 = <instance_public_ip>
  ```

2. Generate test keys. In Key Transparency root directory, run:

  ```sh
  make remote -C testdata
  ```

3. Get [Application Default Credentials](https://developers.google.com/identity/protocols/application-default-credentials)

  Use this [wizard](https://console.developers.google.com/start/api?id=e2ekeys)
  and set ```GOOGLE_APPLICATION_CREDENTIALS``` environment variable in
  [.env](.env) to point to the credentials file.

4. Download and run an XJSON [Certificate Transparency](https://github.com/google/certificate-transparency) Server.

  Set the `CTLOG` variable to the CT server URL in the [.env](.env) file.

5. Configure the server to listen on all IP addressed by setting the `IP` variable in
  [.env](.env) to `*`.

6. Run

  ```sh
  goreman start
  ```

## Using the Key Transparency Client

1. Get a client secret
  Use this [wizard](https://console.developers.google.com/start/api?id=e2ekeys)
  and set the `client_secret` path in `.key-transparency.yaml`

2. Configure Key Transparency cluster IP address in `.key-transparency.yaml` by setting the `kt-url` variable.
  This value is of the form `ip:port`; where `ip` could be either `localhost` or your Google cloud instance public IP (in the examples above),
  and `port` is the port that Key Transparency frontend is listening on.

3. Set/Update a user's keys:

  ```
  ./key-transparency-client post <email> -d '{"app1": "dGVzdA=="}' --config=./.key-transparency.yaml
  {Keys:map[app1:[116 101 115 116]}
  ```

4. Fetch and verify a user's keys:

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

## Installing Protocol Buffers from Scratch
You can install [ProtocolBuffers](https://github.com/golang/protobuf#installation) 3.0 or later by downloading and building the binaries.

1. Ensure that you have `unzip` and `autoreconf` commands installed and operational. On an Ubuntu machine, you can get both by running the following command:

  ```sh
  apt-get install unzip dh-autoreconf
  ```

2. Run

  ```sh
  mkdir tmp
  cd tmp
  git clone https://github.com/google/protobuf
  cd protobuf
  ./autogen.sh
  ./configure
  make
  make check
  sudo make install
  ```
