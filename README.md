# Key Transparency
Key Transparency is a distributed implementation of
[CONIKS](https://eprint.iacr.org/2014/1004.pdf), written in Go.



# Getting Started

## Installation
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
go get -u github.com/google/key-transparency/...
go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway
go get -u github.com/golang/protobuf/protoc-gen-go
```

The shell `$PATH` must include `$GOPATH/bin`

# Running a Key Transparency Cluster
1. Install [goreman](https://github.com/mattn/goreman), which manages 
Procfile-based applications.
```sh
go get -u github.com/mattn/goreman
```

2. Generate test VRF and signing keys.
```sh
make -C testdata
```

3. Get [Application Default Credentials](https://developers.google.com/identity/protocols/application-default-credentials) 
and set ```GOOGLE_APPLICATION_CREDENTIALS``` environment variable in 
[.env](.env) to point to the credentials file.

4. Download and run an XJSON [Certificate Transparency](https://github.com/google/certificate-transparency) Server. 
Set the `CTLOG` variable to the URL of the CT server URL in the [.env](.env) file.

5. Run 
The [Procfile script](./Procfile) will set up a local cluster. Start it with:

```sh
goreman start
```

# Using the Key Transparency Client
1. Fetch and verify a user's keys with:
```sh
./key-transparency-client -ct-url=<url of XJSON CT server> -kt-url=<url of server> -user=email@address.com
``` 




# Projects Using Key Transparency
* [Google End-To-End](https://github.com/google/end-to-end).

