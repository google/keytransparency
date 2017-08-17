FROM golang

ADD keytransparency/genfiles/* /kt/
ADD ./keytransparency /go/src/github.com/google/keytransparency
ADD ./trillian /go/src/github.com/google/trillian
WORKDIR /go/src/github.com/google/keytransparency 

RUN go get -tags="mysql" ./cmd/keytransparency-server

# Image is not runnable without providing a map-id and log-id
# see Readme.md on how to use docker-compose to run this image.

EXPOSE 8080