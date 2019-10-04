FROM golang:1.13 as build

WORKDIR /go/src/github.com/google/keytransparency
COPY go.mod go.sum ./

RUN go mod download
COPY . .

RUN go get ./cmd/keytransparency-sequencer

FROM gcr.io/distroless/base

COPY --from=build /go/bin/keytransparency-sequencer /
ADD ./genfiles/* /kt/

ENTRYPOINT ["/keytransparency-sequencer"]
