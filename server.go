package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
)

// These test keys were generated with the following program, available in the
// crypto/tls directory:
//
//	go run generate_cert.go -ecdsa-curve P256 -host 127.0.0.1 -allowDC
//
var delegatorCertPEMP256 = `-----BEGIN CERTIFICATE-----
MIIBejCCAR+gAwIBAgIQKEg6iMq02QUu7QZSZJ/qjzAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTIxMDIyNzAwMTYwMVoXDTIyMDIyNzAwMTYwMVow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJTe
bU0Yny6aMvae3zlNj135l7XSzqPDZjYh1PqIqY/P2N5PPmD06fHQ2D7xZRUw/a5z
W7KMwRVXrvur+TVn4+GjVzBVMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggr
BgEFBQcDATAMBgNVHRMBAf8EAjAAMA8GCSsGAQQBgtpLLAQCBQAwDwYDVR0RBAgw
BocEfwAAATAKBggqhkjOPQQDAgNJADBGAiEAvkorBgZm6GidD0Z7tcAJWRq+2YOQ
GVclN1Z1CDljQIoCIQDUlTAqDyRpNJ9ntCHEdOQYe1LfAkJHasok5yCRHC1o8w==
-----END CERTIFICATE-----
`

var delegatorKeyPEMP256 = `-----BEGIN EC PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4OgO7q8sUUZaYjEp
JuLzlXH0qmTZ1k3UHgPYbAmRFOWhRANCAASU3m1NGJ8umjL2nt85TY9d+Ze10s6j
w2Y2IdT6iKmPz9jeTz5g9Onx0Ng+8WUVMP2uc1uyjMEVV677q/k1Z+Ph
-----END EC PRIVATE KEY-----
`

func main() {
	// The delegation P256 certificate.
	dcCertP256 := new(tls.Certificate)
	var err error
	*dcCertP256, err = tls.X509KeyPair([]byte(delegatorCertPEMP256), []byte(delegatorKeyPEMP256))
	if err != nil {
		panic(err)
	}

	dcCertP256.Leaf, err = x509.ParseCertificate(dcCertP256.Certificate[0])
	if err != nil {
		panic(err)
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS13,
	}

	// The root certificates for the peer: this are invalid so DO NOT REUSE.
	cfg.RootCAs = x509.NewCertPool()

	dcRoot, err := x509.ParseCertificate(dcCertP256.Certificate[0])
	if err != nil {
		panic(err)
	}
	cfg.RootCAs.AddCert(dcRoot)

	cfg.Certificates = make([]tls.Certificate, 1)
	cfg.Certificates[0] = *dcCertP256

	srv := &http.Server{
		Addr:      ":8443",
		Handler:   &handler{},
		TLSConfig: cfg,
	}
	log.Fatal(srv.ListenAndServeTLS("server.crt", "server.key"))
}

type handler struct{}

func (h *handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Write([]byte("PONG\n"))
}
