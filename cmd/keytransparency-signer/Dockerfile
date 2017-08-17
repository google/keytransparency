FROM golang

ADD keytransparency/genfiles/* /kt/
ADD ./keytransparency /go/src/github.com/google/keytransparency
ADD ./trillian /go/src/github.com/google/trillian
WORKDIR /go/src/github.com/google/keytransparency 

RUN go get -tags="mysql" ./cmd/keytransparency-signer

ENTRYPOINT
  - /go/bin/keytransparency-signer
	- --log-id="$LOG_ID"
	- --log-url="$LOG_URL"
	- --log-key="$LOG_KEY"
	- --map-id="$MAP_ID"
	- --map-url="$MAP_URL"

