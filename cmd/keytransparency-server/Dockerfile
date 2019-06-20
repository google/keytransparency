FROM golang:1.12 as build

WORKDIR /go/src/github.com/google/keytransparency
COPY . .

ENV GO111MODULE=on
RUN go get -tags="mysql" ./cmd/keytransparency-server

FROM gcr.io/distroless/base

COPY --from=build /go/bin/keytransparency-server /
ADD ./genfiles/* /kt/

ENTRYPOINT ["/keytransparency-server"]

EXPOSE 8080
