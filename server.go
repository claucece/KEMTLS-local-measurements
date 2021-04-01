package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
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

func initServer() *tls.Config {
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

	return cfg
}

func initClient() *tls.Config {
	ccfg := &tls.Config{
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // I'm JUST setting this for this test because the root and the leas are the same
	}

	return ccfg
}

func newLocalListener() net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		ln, err = net.Listen("tcp6", "[::1]:0")
	}
	if err != nil {
		log.Fatal(err)
	}
	return ln
}

func testConnWithDC(clientMsg, serverMsg string, clientConfig, serverConfig *tls.Config, peer string) (bool, error) {
	ln := newLocalListener()
	defer ln.Close()

	serverCh := make(chan *tls.Conn, 1)
	var serverErr error
	go func() {
		serverConn, err := ln.Accept()
		if err != nil {
			serverErr = err
			serverCh <- nil
			return
		}
		server := tls.Server(serverConn, serverConfig)
		if err := server.Handshake(); err != nil {
			serverErr = fmt.Errorf("handshake error: %v", err)
			serverCh <- nil
			return
		}
		serverCh <- server
	}()

	client, err := tls.Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		return false, err
	}
	defer client.Close()

	server := <-serverCh
	if server == nil {
		return false, serverErr
	}

	bufLen := len(clientMsg)
	if len(serverMsg) > len(clientMsg) {
		bufLen = len(serverMsg)
	}
	buf := make([]byte, bufLen)

	client.Write([]byte(clientMsg))
	n, err := server.Read(buf)
	if err != nil || n != len(clientMsg) || string(buf[:n]) != clientMsg {
		return false, fmt.Errorf("Server read = %d, buf= %q; want %d, %s", n, buf, len(clientMsg), clientMsg)
	}

	server.Write([]byte(serverMsg))
	n, err = client.Read(buf)
	if n != len(serverMsg) || err != nil || string(buf[:n]) != serverMsg {
		return false, fmt.Errorf("Client read = %d, %v, data %q; want %d, nil, %s", n, err, buf, len(serverMsg), serverMsg)
	}

	return false, nil
}

func main() {
	serverMsg := "hello, client"
	clientMsg := "hello, server"

	serverConfig := initServer()
	clientConfig := initClient()

	_, err := testConnWithDC(clientMsg, serverMsg, clientConfig, serverConfig, "server")
	if err != nil {
		log.Println(err)
	} else {
		log.Println("success")
	}
}
