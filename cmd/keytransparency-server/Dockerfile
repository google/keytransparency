FROM golang:1.13 as build

WORKDIR /go/src/github.com/google/keytransparency
COPY go.mod go.sum ./

RUN go mod download
COPY . .

RUN go get ./cmd/keytransparency-server

FROM gcr.io/distroless/base

COPY --from=build /go/bin/keytransparency-server /

ENTRYPOINT ["/keytransparency-server"]

EXPOSE 8080
