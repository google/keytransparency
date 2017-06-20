FROM mysql:5.7

# expects the build context to be: $GOPATH/src/github.com/google/ (as both,
# trillian and keytransparency, reside there and docker can find the storage.sql
# file)
COPY trillian/storage/mysql/storage.sql /docker-entrypoint-initdb.d/storage.sql