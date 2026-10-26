// Test cases for go-http-server-missing-timeouts (run: make sast-test).
package semgreptest

import (
	"net"
	"net/http"
	"time"
)

func goodServer(h http.Handler) *http.Server {
	// ok: go-http-server-missing-timeouts
	return &http.Server{
		Addr:              ":8080",
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func goodServerOtherOrder(h http.Handler) http.Server {
	// ok: go-http-server-missing-timeouts
	return http.Server{IdleTimeout: time.Minute, WriteTimeout: time.Minute, ReadTimeout: time.Minute, ReadHeaderTimeout: time.Second, Handler: h}
}

func noTimeouts(h http.Handler) *http.Server {
	// ruleid: go-http-server-missing-timeouts
	return &http.Server{Addr: ":8080", Handler: h}
}

func missingReadHeaderTimeout(h http.Handler) *http.Server {
	// ruleid: go-http-server-missing-timeouts
	return &http.Server{
		Handler:      h,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

func missingIdleTimeout(h http.Handler) *http.Server {
	// ruleid: go-http-server-missing-timeouts
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
}

func defaultServer(h http.Handler, ln net.Listener) error {
	// ruleid: go-http-server-missing-timeouts
	_ = http.ListenAndServe(":8080", h)
	// ruleid: go-http-server-missing-timeouts
	return http.Serve(ln, h)
}
