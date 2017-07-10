FROM golang

ENV DB_USER=test \
    DB_PASSWORD=zaphod \
    DB_DATABASE=test \
    DB_HOST=db:3306

ENV HOST=0.0.0.0 \
    RPC_PORT=8080

# TLS Certificate needs 0.0.0.0 to be in the SAN IP field.
ENV VRF_PRIV=keytransparency/genfiles/vrf-key.pem \
    TLS_KEY_PATH=keytransparency/genfiles/server.key \
    TLS_CRT_PATH=keytransparency/genfiles/server.crt

ENV MAP_ID=0 \
    MAP_URL=""
ENV LOG_ID=0 \
    LOG_URL=localhost:8090

ENV VERBOSITY=1

ADD keytransparency/genfiles/* /kt/
ADD ./keytransparency /go/src/github.com/google/keytransparency
ADD ./trillian /go/src/github.com/google/trillian
WORKDIR /go/src/github.com/google/keytransparency 

RUN apt-get update && apt-get install -y libtool libltdl-dev
RUN go get -tags="mysql" ./cmd/keytransparency-server

ENTRYPOINT /go/bin/keytransparency-server \
	--addr="$HOST:$RPC_PORT" \
	--db="${DB_USER}:${DB_PASSWORD}@tcp(${DB_HOST})/${DB_DATABASE}" \
	--vrf="$VRF_PRIV" \
	--key="$TLS_KEY_PATH" --cert="$TLS_CRT_PATH" \
	--log-id="$LOG_ID" --log-url="$LOG_URL" \
	--map-id="$MAP_ID" --map-url="$MAP_URL" \
	--alsologtostderr  \
	--v=${VERBOSITY}

EXPOSE $RPC_PORT

HEALTHCHECK --interval=5m --timeout=3s \
  CMD curl -f http://localhost:$RPC_PORT/debug/vars || exit 1
