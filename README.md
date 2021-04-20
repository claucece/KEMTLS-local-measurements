# KEMTLS local measurements

The scripts needed for KEMTLS local measurements.

## To build

* Build our own version of golang (provided as a submodule) by
  executing `make.bash` in the `go/src` folder.
* To run vanilla tls 1.3 with DC for server authentication only,
  run `go/bin/go run server.go`
* To run vanilla tls 1.3 with DC for mutual authentication,
  run `go/bin/go run client.go`
* To run kemtls with DC for server authentication only,
  run `go/bin/go run server_kemtls.go`
* To run kemtls with DC for mutual authentication,
  run `go/bin/go run client_kemtls.go`
* To run pqtls with DC for server authentication only,
  run `go/bin/go run server_pqtls.go`
* To run pqtls with DC for mutual authentication,
  run `go/bin/go run client_pqtls.go`

