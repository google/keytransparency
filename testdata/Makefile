all: vrf tls sig

tls:
	openssl genrsa -des3 -passout pass:x -out server.pass.key 2048
	openssl rsa -passin pass:x -in server.pass.key -out server.key
	chmod 600 server.key
	rm server.pass.key
	openssl req -new -key server.key -out server.csr \
		  -subj "/C=US/ST=CA/L=MountainView/CN=localhost"
	openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

sig:
	openssl ecparam -name prime256v1 -genkey -noout -out p256-key.pem
	chmod 600 p256-key.pem
	openssl ec -in p256-key.pem -pubout -out p256-pubkey.pem

vrf:
	openssl ecparam -name server.key prime256v1 -genkey -noout -out vrf-key.pem
	chmod 600 vrf-key.pem
	openssl ec -in vrf-key.pem -pubout -out vrf-pubkey.pem

clean:
	find . -type f ! -name 'Makefile' -exec rm -f '{}' \;
