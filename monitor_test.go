package domainsec

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a goroutine-safe writer so the Run goroutine and the test can
// share a log sink without racing.
type syncBuffer struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func newTestMonitor() (Monitor, *syncBuffer) {
	buf := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return NewMonitor(NewService(nil, fakeResolver{}), logger), buf
}

func TestNewMonitor(t *testing.T) {
	m, _ := newTestMonitor()
	if m.logger == nil {
		t.Fatal("NewMonitor did not wire the logger")
	}
	if m.service.resolver == nil {
		t.Fatal("NewMonitor did not wire the service")
	}
}

func TestMonitorCheckLogs(t *testing.T) {
	m, buf := newTestMonitor()
	m.check()
	if !strings.Contains(buf.String(), "domain security monitor check completed") {
		t.Fatalf("check did not log; got %q", buf.String())
	}
}

func TestMonitorRunTicksThenStops(t *testing.T) {
	m, buf := newTestMonitor()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- m.Run(ctx, time.Millisecond) }()

	// Wait until at least one tick has produced a check log, then cancel.
	deadline := time.After(2 * time.Second)
	for !strings.Contains(buf.String(), "check completed") {
		select {
		case <-deadline:
			cancel()
			t.Fatal("monitor never ticked")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}
