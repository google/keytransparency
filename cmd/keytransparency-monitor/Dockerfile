FROM golang

ADD keytransparency/genfiles/* /kt/
ADD ./keytransparency /go/src/github.com/google/keytransparency
ADD ./trillian /go/src/github.com/google/trillian
WORKDIR /go/src/github.com/google/keytransparency 

ENTRYPOINT ["/go/bin/keytransparency-monitor"]

EXPOSE 8099
