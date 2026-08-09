package health

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServe_AnswersHealthAndStopsOnContextCancel(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, listener) }()

	client := &http.Client{Timeout: time.Second}
	var response *http.Response
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		response, err = client.Get("http://" + listener.Addr().String() + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "ok\n" {
		t.Fatalf("GET /healthz = %d %q, want 200 ok", response.StatusCode, body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop after context cancellation")
	}
}

func TestListenAddr_DefaultAndConfigured(t *testing.T) {
	t.Parallel()

	if got := ListenAddr(""); got != ":8080" {
		t.Fatalf("ListenAddr empty = %q, want :8080", got)
	}
	if got := ListenAddr("127.0.0.1:9090"); got != "127.0.0.1:9090" {
		t.Fatalf("ListenAddr configured = %q", got)
	}
}
