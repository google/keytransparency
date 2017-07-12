FROM golang

ENV HOST=0.0.0.0 \
    RPC_PORT=8099

# TLS Certificate needs 0.0.0.0 to be in the SAN IP field.
ENV VRF_PUB=keytransparency/genfiles/vrf-key.pem \
    TLS_KEY_PATH=genfiles/server.key \
    TLS_CRT_PATH=genfiles/server.crt

ENV KT_URL=kt-server:8080

ENV MAP_ID=0 \
    MAP_URL=""
ENV LOG_ID=0 \
    LOG_URL=localhost:8090
ENV MONITOR_SIGN_KEY=TODO \
    POLL_PERIOD=5s

ENV VERBOSITY=1

ADD keytransparency/genfiles/* /kt/
ADD ./keytransparency /go/src/github.com/google/keytransparency
ADD ./trillian /go/src/github.com/google/trillian
WORKDIR /go/src/github.com/google/keytransparency 

RUN apt-get update && apt-get install -y libtool libltdl-dev
RUN go get -tags="mysql" ./cmd/keytransparency-monitor

ENTRYPOINT /go/bin/keytransparency-monitor \
	--addr="$HOST:$RPC_PORT" --kt-url="$KT_URL" --poll-period="$POLL_PERIOD" \
	--vrf="$VRF_PUB" \
	--key="$TLS_KEY_PATH" --cert="$TLS_CRT_PATH" \
	--log-id="$LOG_ID" --log-key="$LOG_PUB_KEY" \
	--map-id="$MAP_ID" \
	--alsologtostderr  \
	--v=${VERBOSITY}

EXPOSE $RPC_PORT

#HEALTHCHECK --interval=5m --timeout=3s \
#  CMD curl -f http://localhost:$RPC_PORT/TODO || exit 1
