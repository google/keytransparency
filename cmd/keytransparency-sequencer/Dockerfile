FROM golang:1.13 as build

WORKDIR /go/src/github.com/google/keytransparency
COPY go.mod go.sum ./

RUN go mod download
COPY . .

RUN go get ./cmd/keytransparency-sequencer
RUN go get ./cmd/healthcheck

FROM gcr.io/distroless/base

COPY --from=build /go/bin/keytransparency-sequencer /
COPY --from=build /go/bin/healthcheck /

ENTRYPOINT ["/keytransparency-sequencer"]
HEALTHCHECK CMD ["/healthcheck","http://localhost:8081/healthz"]

EXPOSE 8080
EXPOSE 8081
