FROM golang:1.13 as build

WORKDIR /go/src/github.com/google/keytransparency
COPY go.mod go.sum ./

RUN go mod download
COPY . .

RUN go get ./cmd/keytransparency-monitor
RUN go get ./cmd/healthcheck

FROM gcr.io/distroless/base

COPY --from=build /go/bin/keytransparency-monitor /
COPY --from=build /go/bin/healthcheck /

ENTRYPOINT ["/keytransparency-monitor"]
HEALTHCHECK CMD ["/healthcheck","http://localhost:8071/healthz"]

EXPOSE 8070
EXPOSE 8071
