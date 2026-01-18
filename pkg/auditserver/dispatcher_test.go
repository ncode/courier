package auditserver

import (
	"io"
	"log/slog"
	"sort"
	"testing"
	"time"
)

func TestDispatcher_DedupWhilePending(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))

	callCh := make(chan string, 2)
	releaseCh := make(chan chan struct{}, 4)

	dispatcher := NewDispatcher(logger, func(event UpdateEvent) error {
		callCh <- string(event.Kind) + ":" + event.Path + ":" + event.Operation
		release := <-releaseCh
		<-release
		return nil
	}, 1, 1)

	firstRelease := make(chan struct{})
	releaseCh <- firstRelease
	dispatcher.Enqueue(UpdateEvent{Kind: UpdateKindKV, Path: "secret/foo", Operation: "create"})

	select {
	case <-callCh:
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("expected first worker to start")
	}

	dispatcher.Enqueue(UpdateEvent{Kind: UpdateKindKV, Path: "secret/foo", Operation: "update"})

	select {
	case <-callCh:
		t.Fatalf("duplicate worker started while path was pending")
	case <-time.After(25 * time.Millisecond):
	}

	close(firstRelease)
	time.Sleep(20 * time.Millisecond)

	secondRelease := make(chan struct{})
	releaseCh <- secondRelease
	dispatcher.Enqueue(UpdateEvent{Kind: UpdateKindKV, Path: "secret/foo", Operation: "update"})

	select {
	case <-callCh:
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("expected worker to start after pending cleared")
	}

	close(secondRelease)
}

func TestDispatcher_ConcurrentDistinctPaths(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	started := make(chan string, 2)
	block := make(chan struct{})

	dispatcher := NewDispatcher(logger, func(event UpdateEvent) error {
		started <- string(event.Kind) + ":" + event.Path + ":" + event.Operation
		<-block
		return nil
	}, 2, 2)

	dispatcher.Enqueue(UpdateEvent{Kind: UpdateKindKV, Path: "secret/a", Operation: "create"})
	dispatcher.Enqueue(UpdateEvent{Kind: UpdateKindPolicy, Path: "secret/a", Operation: "update"})

	var got []string
	for i := 0; i < 2; i++ {
		select {
		case v := <-started:
			got = append(got, v)
		case <-time.After(50 * time.Millisecond):
			t.Fatalf("expected both workers to start")
		}
	}

	sort.Strings(got)
	expected := []string{"kv:secret/a:create", "policy:secret/a:update"}
	if len(got) != len(expected) {
		t.Fatalf("expected %d workers, got %d", len(expected), len(got))
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Fatalf("unexpected worker: got %v want %v", got, expected)
		}
	}

	close(block)
}

func TestDispatcher_DeadLetterOnFullQueue(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	started := make(chan struct{})
	release := make(chan struct{})

	dispatcher := NewDispatcher(logger, func(event UpdateEvent) error {
		started <- struct{}{}
		<-release
		return nil
	}, 1, 1)

	dispatcher.Enqueue(UpdateEvent{Kind: UpdateKindKV, Path: "secret/a", Operation: "create"}) // occupies worker
	dispatcher.Enqueue(UpdateEvent{Kind: UpdateKindKV, Path: "secret/b", Operation: "create"}) // fills queue
	dispatcher.Enqueue(UpdateEvent{Kind: UpdateKindKV, Path: "secret/c", Operation: "create"}) // should go to dead letter and clear pending

	select {
	case <-started:
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("expected first worker to start")
	}

	close(release)

	// Allow worker to finish and pending to clear before re-enqueueing dead-lettered item.
	time.Sleep(10 * time.Millisecond)
	dispatcher.Enqueue(UpdateEvent{Kind: UpdateKindKV, Path: "secret/c", Operation: "create"})

	select {
	case <-started:
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("expected dead-lettered item to be re-enqueued after completion")
	}
}
