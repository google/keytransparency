FROM golang:1.12 as build

WORKDIR /go/src/github.com/google/keytransparency
COPY go.mod go.sum ./

ENV GO111MODULE=on
RUN go mod download
COPY . .

RUN go get ./cmd/keytransparency-server

FROM gcr.io/distroless/base

COPY --from=build /go/bin/keytransparency-server /

ENTRYPOINT ["/keytransparency-server"]

EXPOSE 8080
