//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package runtime

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"golang.org/x/net/http2"
)

var defaultHTTPClient *http.Client

type loggingRoundTripper struct {
	rt http.RoundTripper
}

func (l loggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return nil, err
	}
	log.Printf("Request: %s", dump)
	return l.rt.RoundTrip(req)
}

func init() {
	defaultTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: defaultTransportDialContext(&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:    tls.VersionTLS12,
			Renegotiation: tls.RenegotiateFreelyAsClient,
		},
	}
	// TODO: evaluate removing this once https://github.com/golang/go/issues/59690 has been fixed
	if http2Transport, err := http2.ConfigureTransports(defaultTransport); err == nil {
		// if the connection has been idle for 10 seconds, send a ping frame for a health check
		http2Transport.ReadIdleTimeout = 10 * time.Second
		// if there's no response to the ping within the timeout, the connection will be closed
		http2Transport.PingTimeout = 5 * time.Second
	}
	defaultHTTPClient = &http.Client{
		Transport: loggingRoundTripper{defaultTransport},
	}

}
