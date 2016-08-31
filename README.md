# Key Transparency
Key Transparency is a distributed implementation of
[CONIKS](https://eprint.iacr.org/2014/1004.pdf), written in Go.


# Running a Key Transparency Cluster
1. Install prerequisites
```sh
go get -u github.com/google/key-transparency/cmd/...
go get -u github.com/mattn/goreman
go get -u github.com/coreos/etcd
```
Ensure `$GOBIN` is in your `$PATH`

2. Generate test keys
```sh
make -C testdata
```
3. Get [Application Default Credentials](https://developers.google.com/identity/protocols/application-default-credentials)
with this [wizard](https://console.developers.google.com/start/api?id=e2ekeys)
and set ```GOOGLE_APPLICATION_CREDENTIALS``` environment variable in
[.env](.env) to point to the credentials file.
4. Download and run an XJSON [Certificate Transparency](https://github.com/google/certificate-transparency) Server.
Set the `CTLOG` variable to the URL of the CT server URL in the [.env](.env) file.
5. Run
```sh
goreman start
```

# Using the Key Transparency Client
1. Get a client secret with this
[wizard](https://console.developers.google.com/start/api?id=e2ekeys)
and set the `client_secret` path in `.key-transparency.yaml`
1. Fetch and verify a user's keys with:
```sh
./key-transparency-client post <email> -d '{"app1": "dGVzdA=="}' --config=./.key-transparency.yaml
./key-transparency-client get <email> --config=.key-transparency.yaml
```

# Building from scratch
Install [ProtocolBuffers](https://github.com/golang/protobuf#installation) 3.0 or later.
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
go get -u github.com/google/key-transparency/cmd/...
go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway
go get -u github.com/golang/protobuf/protoc-gen-go
```



# Projects Using Key Transparency
* [Google End-To-End](https://github.com/google/end-to-end).
