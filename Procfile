# Use goreman to run `go get github.com/mattn/goreman`
etcd1: etcd --name infra1 --listen-client-urls $LISTEN1 --advertise-client-urls $LISTEN1 --listen-peer-urls $PEER1 --initial-advertise-peer-urls $PEER1 --enable-pprof 
etcd2: etcd --name infra2 --listen-client-urls $LISTEN2 --advertise-client-urls $LISTEN2 --listen-peer-urls $PEER2 --initial-advertise-peer-urls $PEER2 --enable-pprof
etcd3: etcd --name infra3 --listen-client-urls $LISTEN3 --advertise-client-urls $LISTEN3 --listen-peer-urls $PEER3 --initial-advertise-peer-urls $PEER3 --enable-pprof
web: ./e2e-key-server --port=$PORT --key=$KEY --cert=$CERT --domain=$DOMAIN --db=$DB --maplog=$CTLOG --etcd=$LISTEN --vrf=$VRF_PRIV -logtostderr=true
sign: ./e2e-key-signer --domain=$DOMAIN --db=$DB  --maplog=$CTLOG --etcd=$LISTEN --period=$SIGN_PERIOD_SEC
