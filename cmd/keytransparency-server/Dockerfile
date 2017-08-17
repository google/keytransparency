FROM golang

ADD keytransparency/genfiles/* /kt/
ADD ./keytransparency /go/src/github.com/google/keytransparency
ADD ./trillian /go/src/github.com/google/trillian
WORKDIR /go/src/github.com/google/keytransparency 

RUN go get -tags="mysql" ./cmd/keytransparency-server

ENTRYPOINT
  - /go/bin/keytransparency-server
	- --log-id="$LOG_ID"
	- --log-url="$LOG_URL" \
	- --map-url="$MAP_URL" \
	- --alsologtostderr

EXPOSE 8080