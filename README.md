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
go get -u github.com/gengo/grpc-gateway/protoc-gen-grpc-gateway
go get -u github.com/golang/protobuf/protoc-gen-go
go get -u github.com/mattn/goreman
```

And the shell $PATH must include $GOPATH/bin

Running a Key Transparency Cluster
----------------------------------
First install [goreman](https://github.com/mattn/goreman), which manages Procfile-based applications.

The [Procfile script](./Procfile) will set up a local cluster. Start it with:

```sh
make -C testdata
goreman start
```

Getting OAuth Credentials 
-----------------
1. Use this [wizard](https://console.developers.google.com/start/api?id=drive)
   to create or select a project in the Google Developers Console and
   automatically turn on the API. Click **Continue**, then **Go to credentials**.
2. At the top of the page, select the **OAuth consent screen tab**. Select an 
   **Email address**, enter a **Product name** if not already set, and click the 
   **Save** button.
3. Select the **Credentials** tab, click the **Create credentials** button and 
   select **OAuth client ID**.
4. Select the application type **Other**, enter the name "Key Transparency 
   Server", and click the Create button.
5. Click OK to dismiss the resulting dialog.
6. Click the file_download (Download JSON) button to the right of the client ID.
7. Move this file to your working directory and rename it client_secret.json.
8. Set the ```CLIENT_SECRETS``` variable in [.env](.env) with the path to client_secrets.json.


Projects Using Key Transparency
==================================
* [Google End-To-End](https://github.com/google/end-to-end).

