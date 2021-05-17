module github.com/google/keytransparency

go 1.12

require (
	cloud.google.com/go/spanner v1.7.0
	github.com/VividCortex/mysqlerr v0.0.0-20170204212430-6c6b55f8796f
	github.com/coreos/go-systemd v0.0.0-20190719114852-fd7a80b32e1f // indirect
	github.com/go-kit/kit v0.9.0
	github.com/go-sql-driver/mysql v1.6.0
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/mock v1.5.0
	github.com/golang/protobuf v1.5.2
	github.com/google/certificate-transparency-go v1.1.0 // indirect
	github.com/google/go-cmp v0.5.5
	github.com/google/tink/go v1.4.0-rc2
	github.com/google/trillian v1.3.10
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.0
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/grpc-ecosystem/grpc-gateway v1.14.6
	github.com/kr/pretty v0.1.0
	github.com/kylelemons/godebug v1.1.0
	github.com/pelletier/go-toml v1.6.0 // indirect
	github.com/prometheus/client_golang v1.7.1
	github.com/sirupsen/logrus v1.6.0 // indirect
	github.com/spf13/cobra v0.0.7
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.0
	gocloud.dev v0.23.0
	golang.org/x/crypto v0.0.0-20210506145944-38f3c27a63bf
	golang.org/x/oauth2 v0.0.0-20210427180440-81ed05c6b58c
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba
	google.golang.org/api v0.46.0
	google.golang.org/genproto v0.0.0-20210506142907-4a47615972c2
	google.golang.org/grpc v1.37.0
	google.golang.org/protobuf v1.26.0
	gopkg.in/yaml.v2 v2.2.8 // indirect
)

replace go.etcd.io/etcd => go.etcd.io/etcd v0.0.0-20200513171258-e048e166ab9c
