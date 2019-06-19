FROM golang:1.12 as build

WORKDIR /go/src/github.com/google/keytransparency
COPY . .

ENV GO111MODULE=on
RUN go get -tags="mysql" ./cmd/keytransparency-monitor

FROM gcr.io/distroless/base

COPY --from=build /go/bin/keytransparency-monitor /
ADD ./genfiles/* /kt/

ENTRYPOINT ["/keytransparency-monitor"]

EXPOSE 8099
