package audit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestWriteAndRead(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	defer w.Close()

	for i := 0; i < 3; i++ {
		e := Event{
			ID:       fmt.Sprintf("evt-%d", i),
			Time:     time.Unix(int64(1700000000+i), 0).UTC(),
			Actor:    "alice",
			Action:   "read",
			Resource: fmt.Sprintf("doc/%d", i),
		}
		if err := w.Write(e); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if w.Count() != 3 {
		t.Fatalf("count = %d, want 3", w.Count())
	}

	got, err := ReadAll(dir)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("events = %d, want 3", len(got))
	}
	if got[0].ID != "evt-0" || got[2].Resource != "doc/2" {
		t.Fatalf("unexpected content: %+v", got)
	}
}

func TestWriteRequiresID(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	defer w.Close()

	if err := w.Write(Event{Actor: "bob", Action: "write"}); err == nil {
		t.Fatal("expected error for empty id, got nil")
	}
}

func TestConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	defer w.Close()

	const goroutines = 8
	const perG = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				_ = w.Write(Event{
					ID:       fmt.Sprintf("g%d-%d", g, i),
					Actor:    "carol",
					Action:   "update",
					Resource: "doc/x",
				})
			}
		}(g)
	}
	wg.Wait()

	got, err := ReadAll(dir)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if len(got) != goroutines*perG {
		t.Fatalf("events = %d, want %d (corrupt or lost)", len(got), goroutines*perG)
	}
}
