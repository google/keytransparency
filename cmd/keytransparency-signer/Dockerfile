FROM golang

ENV DB_USER=test \
    DB_PASSWORD=zaphod \
    DB_DATABASE=test \
    DB_HOST=127.0.0.0:3306

ENV MAP_ID=0 \
    MAP_URL=""
ENV LOG_ID=0 \
    LOG_URL=localhost:8090 \
    LOG_KEY=../trillian/testdata/log-rpc-server.pubkey.pem

ENV MIN_SIGN_PERIOD=5s \
    MAX_SIGN_PERIOD=24h

ENV VERBOSITY=0

ADD trillian/testdata/* /trillian/
ADD ./keytransparency /go/src/github.com/google/keytransparency
WORKDIR /go/src/github.com/google/keytransparency 

RUN go get -tags="mysql" ./cmd/keytransparency-signer

ENTRYPOINT /go/bin/keytransparency-signer \
	--db="${DB_USER}:${DB_PASSWORD}@tcp(${DB_HOST})/${DB_DATABASE}" \
	--min-period="$MIN_SIGN_PERIOD" --max-period="$MAX_SIGN_PERIOD" \
        --key="$SIGN_KEY" --password="$SIGN_KEY_PW" \
	--log-id="$LOG_ID" --log-url="$LOG_URL" --log-key="$LOG_KEY" \
	--map-id="$MAP_ID" --map-url="$MAP_URL" \
	--alsologtostderr --v=${VERBOSITY}

