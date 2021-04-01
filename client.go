package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	ccfg := &tls.Config{
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // I'm JUST setting this for this test because the root and the leas are the same
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: ccfg,
		},
	}

	resp, err := client.Get("https://localhost:8443")
	if err != nil {
		log.Println(err)
		return
	}

	htmlData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("%v\n", resp.Status)
	fmt.Printf(string(htmlData))
}
