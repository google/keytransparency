Key Transparency
================
Key Transparency is a distributed implementation of
[CONIKS](https://eprint.iacr.org/2014/1004.pdf), written in Go.



Getting Started
===============

Installation
------------------------
First you need to install [ProtocolBuffers](https://github.com/golang/protobuf#installation) 3.0 or later.
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

Then, ```go get -u``` as usual

```sh
go get -u github.com/google/e2e-key-server/...
go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway
go get -u github.com/golang/protobuf/protoc-gen-go
go get -u github.com/mattn/goreman
```

And the shell $PATH must include $GOPATH/bin

Running a Key Transparency Cluster
----------------------------------
1. Install [goreman](https://github.com/mattn/goreman), which manages 
Procfile-based applications.

2. Generate test VRF and signing keys.
```sh
make -C testdata
```

3. Get [Application Default Credentials](https://developers.google.com/identity/protocols/application-default-credentials) 
and set ```GOOGLE_APPLICATION_CREDENTIALS``` environment variable in 
[.env](.env) to point to the credentials file.

4. Run 
The [Procfile script](./Procfile) will set up a local cluster. Start it with:

```sh
make -C testdata
goreman start
```

Projects Using Key Transparency
==================================
* [Google End-To-End](https://github.com/google/end-to-end).

