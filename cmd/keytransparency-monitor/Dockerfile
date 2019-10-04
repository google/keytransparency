FROM golang:1.13 as build

WORKDIR /go/src/github.com/google/keytransparency
COPY go.mod go.sum ./

RUN go mod download
COPY . .

RUN go get -tags="mysql" ./cmd/keytransparency-monitor

FROM gcr.io/distroless/base

COPY --from=build /go/bin/keytransparency-monitor /

ENTRYPOINT ["/keytransparency-monitor"]

EXPOSE 8099
