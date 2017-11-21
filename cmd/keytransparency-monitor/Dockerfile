FROM golang:1.9

ADD keytransparency/genfiles/* /kt/
ADD ./keytransparency /go/src/github.com/google/keytransparency
ADD ./trillian /go/src/github.com/google/trillian
WORKDIR /go/src/github.com/google/keytransparency 

RUN go get -tags="mysql" ./cmd/keytransparency-monitor

ENTRYPOINT ["/go/bin/keytransparency-monitor"]

EXPOSE 8099
