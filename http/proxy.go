package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"time"

	"github.com/fasmide/remotemoe/services"
)

// Proxy reverse proxies requests though router
type Proxy struct {
	httputil.ReverseProxy
}

// Dialer interface describes the minimun methods a Proxy needs
type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// Initialize sets up this proxy's transport to dial though
// Router instead of doing classic network dials
func (h *Proxy) Initialize(router Dialer) {
	transport := &http.Transport{
		DialContext:           router.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxConnsPerHost:       10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// TLS inside the ssh tunnel will not be able to provide any valid certificate so ..
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// This director will try to set r.URL to something
	// useful based on the "virtualhost" and the destination tcp port
	h.Director = func(r *http.Request) {

		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}

		localAddr := r.Context().Value(localAddr("localaddr")).(string)
		_, dstPort, _ := net.SplitHostPort(localAddr)

		r.URL.Host = fmt.Sprintf("%s:%s", host, dstPort)

		// cant possibly fail right? :)
		dPort, _ := strconv.Atoi(dstPort)

		// services.Ports should map 80 into http, 443 into https and so on
		r.URL.Scheme = services.Ports[dPort]
	}

	h.Transport = transport

}
