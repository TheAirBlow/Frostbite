package spec

import (
	"net"
	"regexp"
	"strconv"
)

// NaiveDefaultHeader carries the visitor's address to the site when the inbound names no other header.
const NaiveDefaultHeader = "X-Forwarded-For"

// NaiveNoHeader turns the client address header off.
const NaiveNoHeader = "none"

// headerName matches an HTTP header name, which is a token.
var headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

// NaiveIPHeader resolves the header the visitor's address goes in, empty when none is sent.
func (o Options) NaiveIPHeader() string {
	switch o.NaiveHeader {
	case "":
		return NaiveDefaultHeader
	case NaiveNoHeader:
		return ""
	}
	return o.NaiveHeader
}

// validateNaive checks the settings of an inbound served by the naive daemon, which sends visitors that are no
// proxy users on to a real site.
func (o Options) validateNaive() error {
	host, port, err := net.SplitHostPort(o.NaiveDest)
	if err != nil || host == "" {
		return Invalid("options.naive_dest", "the site address must look like host:port")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return Invalid("options.naive_dest", "the site port must be 1 to 65535")
	}
	switch o.NaiveProxy {
	case "", "v1", "v2":
	default:
		return Invalid("options.naive_dest_proxy", "the PROXY protocol version must be v1 or v2, or empty for none")
	}
	if o.NaiveHeader != "" && o.NaiveHeader != NaiveNoHeader && !headerName.MatchString(o.NaiveHeader) {
		return Invalid("options.naive_ip_header", "%q is not a valid header name", o.NaiveHeader)
	}
	return nil
}
