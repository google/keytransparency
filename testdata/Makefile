all:
	go run ../vrf/vrfkeygen/vrfkeygen.go
	openssl genrsa -des3 -passout pass:x -out server.pass.key 2048
	openssl rsa -passin pass:x -in server.pass.key -out server.key
	rm server.pass.key
	openssl req -new -key server.key -out server.csr \
		  -subj "/C=US/ST=CA/L=MountainView/CN=localhost"
	openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

clean:
	ls | grep -v Makefile | xargs rm

