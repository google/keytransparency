FROM golang:1.13 as build

WORKDIR /go/src/github.com/google/keytransparency
COPY go.mod go.sum ./

RUN go mod download
COPY . .

RUN go get ./cmd/keytransparency-monitor
RUN go get ./cmd/healthcheck

FROM gcr.io/distroless/base

COPY --from=build /go/bin/keytransparency-monitor /

ENTRYPOINT ["/keytransparency-monitor"]
HEALTHCHECK CMD ["/healthcheck","https://localhost:8099/healthz"]

EXPOSE 8099
