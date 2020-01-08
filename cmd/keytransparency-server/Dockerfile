FROM golang:1.13 as build

WORKDIR /go/src/github.com/google/keytransparency
COPY go.mod go.sum ./

RUN go mod download
COPY . .

RUN go get ./cmd/keytransparency-server
RUN go get ./cmd/healthcheck

FROM gcr.io/distroless/base

COPY --from=build /go/bin/keytransparency-server /
COPY --from=build /go/bin/healthcheck /

ENTRYPOINT ["/keytransparency-server"]
HEALTHCHECK CMD ["/healthcheck","http://localhost:8081/healthz"]

EXPOSE 8080
EXPOSE 8081
