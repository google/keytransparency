FROM golang:1

ADD ./keytransparency /go/src/github.com/google/keytransparency
ADD ./trillian /go/src/github.com/google/trillian
WORKDIR /go/src/github.com/google/keytransparency 

RUN go get -tags="mysql" ./cmd/keytransparency-sequencer

# Specify mandatory flags via the docker command-line or using docker-compose.
# See the README.md file on how to use docker-compose.
ENTRYPOINT ["/go/bin/keytransparency-sequencer"]
