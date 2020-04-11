// Copyright (C) 2017 Michał Matczuk
// Use of this source code is governed by an AGPL-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
)

const usage1 string = `Usage: tunneld [OPTIONS]
options:
`

const usage2 string = `
Example:
	tunneld
	tunneld -clients YMBKT3V-ESUTZ2Z-7MRILIJ-T35FHGO-D2DHO7D-FXMGSSR-V4LBSZX-BNDONQ4
	tunneld -httpAddr :8080 -httpsAddr ""
	tunneld -httpsAddr "" -sniAddr ":443" -rootCA client_root.crt -tlsCrt server.crt -tlsKey server.key

Author:
	Written by M. Matczuk (mmatczuk@gmail.com)

Bugs:
	Submit bugs to https://github.com/mmatczuk/go-http-tunnel/issues
`

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usage1)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, usage2)
	}
}

// options specify arguments read command line arguments.
type options struct {
	httpAddr   string
	httpsAddr  string
	tunnelAddr string
	apiAddr    string
	sniAddr    string
	tlsCrt     string
	tlsKey     string
	rootCA     string
	portRange  string
	logLevel   int
	version    bool
}

func parseArgs() *options {
	httpAddr := flag.String("httpAddr", ":80", "Public address for HTTP connections, empty string to disable")
	httpsAddr := flag.String("httpsAddr", ":443", "Public address listening for HTTPS connections, emptry string to disable")
	tunnelAddr := flag.String("tunnelAddr", ":5223", "Public address listening for tunnel client")
	apiAddr := flag.String("apiAddr", ":5091", "Public address for HTTP API to get tunnels info")
	sniAddr := flag.String("sniAddr", "", "Public address listening for TLS SNI connections, empty string to disable")
	tlsCrt := flag.String("tlsCrt", "server.crt", "Path to a TLS certificate file")
	tlsKey := flag.String("tlsKey", "server.key", "Path to a TLS key file")
	rootCA := flag.String("rootCA", "", "Path to the trusted certificate chian used for client certificate authentication, if empty any client certificate is accepted")
	portRange := flag.String("portRange", "10000:12000", "Range in format [first:last] of number ports to AUTO assing if client set address as '<somip>:AUTO'")
	logLevel := flag.Int("log-level", 1, "Level of messages to log, 0-3")
	version := flag.Bool("version", false, "Prints tunneld version")
	flag.Parse()

	return &options{
		httpAddr:   *httpAddr,
		httpsAddr:  *httpsAddr,
		tunnelAddr: *tunnelAddr,
		apiAddr:    *apiAddr,
		sniAddr:    *sniAddr,
		tlsCrt:     *tlsCrt,
		tlsKey:     *tlsKey,
		rootCA:     *rootCA,
		portRange:  *portRange,
		logLevel:   *logLevel,
		version:    *version,
	}
}
