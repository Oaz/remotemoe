package services

import (
	"log"
	"net"
)

type server interface {
	Serve(net.Listener) error
}

type tLSServer interface {
	ServeTLS(net.Listener, string, string) error
}

// Serve takes in a server and makes it serve
func Serve(t string, s server) {
	for _, port := range Services[t] {
		go func(t string, p int) {
			l, err := net.ListenTCP("tcp", &net.TCPAddr{Port: p})
			if err != nil {
				// listen errors are usually not a big deal, maybe the user just
				// dont have permissions on privileged-ports but we are still able to work
				// on higher portnumbers
				log.Printf("cannot accept %s on %d: %s", t, p, err)
				return
			}

			log.Printf("accepting %s on %d", t, p)

			err = s.Serve(l)
			if err != nil {
				log.Printf("%s on port %d stopped serving with error: %s", t, p, err)
			}

		}(t, port)
	}
}

// ServeTLS takes in a tls capable server and makes it serve
func ServeTLS(t string, s tLSServer) {
	for _, port := range Services[t] {
		go func(t string, p int) {
			l, err := net.ListenTCP("tcp", &net.TCPAddr{Port: p})
			if err != nil {
				// listen errors are usually not a big deal, maybe the user just
				// dont have permissions on privileged-ports but we are still able to work
				// on higher portnumbers
				log.Printf("cannot accept %s on %d: %s", t, p, err)
				return
			}

			log.Printf("accepting %s on %d", t, p)

			err = s.ServeTLS(l, "", "")
			if err != nil {
				log.Printf("%s on port %d stopped serving with error: %s", t, p, err)
			}

		}(t, port)
	}
}
