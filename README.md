# KEMTLS local measurements

The scripts needed for KEMTLS local measurements.

## To build

* Make sure you have `go 1.16` installed.
* Clone the library with submodules:
  `git clone --recurse-submodules git@github.com:claucece/KEMTLS-local-measurements.git`
  (with ssh in this case).
* Install go-color: `go get -u github.com/TwinProduction/go-color`.
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

