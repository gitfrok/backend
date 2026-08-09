// Package health provides the minimal lifecycle endpoint common to both plane
// binaries. It deliberately exposes no application data or authorization path.
package health

import (
	"context"
	"errors"
	"net"
	"net/http"
)

const defaultListenAddr = ":8080"

// ListenAddr returns the configured listener address, or the container port
// used by the dev deployment when no environment override is supplied.
func ListenAddr(configured string) string {
	if configured == "" {
		return defaultListenAddr
	}
	return configured
}

// Run binds addr and serves a health endpoint until ctx is cancelled.
func Run(ctx context.Context, addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return Serve(ctx, listener)
}

// Serve answers readiness/liveness checks and shuts down cleanly when ctx is
// cancelled. Callers supply the listener so integration tests can use a
// conflict-free ephemeral port.
func Serve(ctx context.Context, listener net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})

	server := &http.Server{Handler: mux}
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Shutdown(context.Background())
		case <-stopped:
		}
	}()

	err := server.Serve(listener)
	close(stopped)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
