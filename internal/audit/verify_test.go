package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeEvents(t *testing.T, w *Writer, n int, hour time.Time, prefix string) {
	t.Helper()
	for i := 0; i < n; i++ {
		e := Event{
			ID:       fmt.Sprintf("%s-%d", prefix, i),
			Time:     hour.Add(time.Duration(i) * time.Second),
			Actor:    "alice",
			Action:   "read",
			Resource: fmt.Sprintf("doc/%d", i),
		}
		if err := w.Write(e); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
}

func mustFlushAndClose(t *testing.T, w *Writer) {
	t.Helper()
	if err := w.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func readFileLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	s := strings.TrimSuffix(string(raw), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func writeFileLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestVerifyIntactAndSealed(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	writeEvents(t, w, 100, time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC), "a")
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatalf("verify active: %v", err)
	}
	if !rep.OK {
		t.Fatalf("expected OK, got issues: %+v", rep.Issues)
	}
	if rep.Checked.Records != 100 {
		t.Fatalf("records = %d, want 100", rep.Checked.Records)
	}

	if err := w.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	segments, err := filepath.Glob(filepath.Join(dir, wormDir, "*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) != 1 {
		t.Fatalf("sealed segments = %d, want 1", len(segments))
	}

	rep, err = Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatalf("verify sealed: %v", err)
	}
	if !rep.OK {
		t.Fatalf("expected OK after seal, got %+v", rep.Issues)
	}
	if len(rep.Segments) != 1 || !rep.Segments[0].OK {
		t.Fatalf("bad segment summary: %+v", rep.Segments)
	}
	if rep.Head.Seq != 100 || rep.Head.Hash == "" {
		t.Fatalf("bad head: %+v", rep.Head)
	}
	mustFlushAndClose(t, w)
}

func TestTamperContentActive(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	writeEvents(t, w, 50, time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC), "a")
	mustFlushAndClose(t, w)

	path := filepath.Join(dir, activeFile)
	lines := readFileLines(t, path)
	idx := 20
	lines[idx] = strings.Replace(lines[idx], `"actor":"alice"`, `"actor":"mallory"`, 1)
	writeFileLines(t, path, lines)

	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("expected tamper detection")
	}
	if rep.FirstTampered == nil {
		t.Fatal("missing first_tampered")
	}
	if rep.FirstTampered.Type != IssueContentModified {
		t.Fatalf("type = %s, want %s", rep.FirstTampered.Type, IssueContentModified)
	}
	if rep.FirstTampered.Seq != uint64(idx+1) {
		t.Fatalf("seq = %d, want %d", rep.FirstTampered.Seq, idx+1)
	}
	if rep.FirstTampered.Position.Line != idx+1 {
		t.Fatalf("line = %d, want %d", rep.FirstTampered.Position.Line, idx+1)
	}
	if rep.AffectedInterval == nil || rep.AffectedInterval.FromSeq != uint64(idx+1) {
		t.Fatalf("bad affected interval: %+v", rep.AffectedInterval)
	}
}

func TestTamperDeleteActive(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	writeEvents(t, w, 50, time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC), "a")
	mustFlushAndClose(t, w)

	path := filepath.Join(dir, activeFile)
	lines := readFileLines(t, path)
	removed := lines[10]
	lines = append(lines[:10], lines[11:]...)
	writeFileLines(t, path, lines)

	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("expected deletion detection")
	}
	if rep.FirstTampered == nil || rep.FirstTampered.Type != IssueRecordDeletion {
		t.Fatalf("unexpected first tampered: %+v", rep.FirstTampered)
	}
	// 被删除的是 seq 11，检测点在下一条记录（原 seq 12）。
	if rep.AffectedInterval == nil || rep.AffectedInterval.FromSeq != 11 {
		t.Fatalf("affected interval = %+v, want from 11", rep.AffectedInterval)
	}
	for _, is := range rep.Issues {
		if is.Type == IssueSegmentMissing {
			t.Fatalf("unexpected segment missing: %+v", is)
		}
	}
	_ = removed
}

func TestTamperReorderActive(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	writeEvents(t, w, 20, time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC), "a")
	mustFlushAndClose(t, w)

	path := filepath.Join(dir, activeFile)
	lines := readFileLines(t, path)
	lines[5], lines[6] = lines[6], lines[5]
	writeFileLines(t, path, lines)

	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("expected reorder detection")
	}
	if rep.FirstTampered == nil {
		t.Fatal("missing first_tampered")
	}
	// 第一条异常可能被判为链断裂/乱序，受影响区间应覆盖 6..7。
	if rep.AffectedInterval == nil || rep.AffectedInterval.FromSeq != 6 {
		t.Fatalf("affected interval = %+v, want from 6", rep.AffectedInterval)
	}
}

func TestTamperSealedFile(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriterWithOptions(dir, Options{WORMImmutable: false})
	if err != nil {
		t.Fatal(err)
	}
	writeEvents(t, w, 30, time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC), "a")
	if err := w.Seal(); err != nil {
		t.Fatal(err)
	}
	mustFlushAndClose(t, w)

	segments, _ := filepath.Glob(filepath.Join(dir, wormDir, "*.jsonl"))
	if len(segments) != 1 {
		t.Fatalf("segments = %d", len(segments))
	}
	lines := readFileLines(t, segments[0])
	lines[12] = strings.Replace(lines[12], `"resource":"doc/12"`, `"resource":"doc/evil"`, 1)
	writeFileLines(t, segments[0], lines)

	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("expected sealed tamper detection")
	}
	if rep.FirstTampered == nil || rep.FirstTampered.Seq != 13 {
		t.Fatalf("first tampered = %+v, want seq 13", rep.FirstTampered)
	}
	if rep.Segments[0].OK {
		t.Fatal("segment should be marked bad")
	}
}

func TestTamperMissingSegment(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriterWithOptions(dir, Options{WORMImmutable: false})
	if err != nil {
		t.Fatal(err)
	}
	writeEvents(t, w, 40, time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC), "a")
	if err := w.Seal(); err != nil {
		t.Fatal(err)
	}
	// 第二个小时
	writeEvents(t, w, 40, time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC), "b")
	if err := w.Seal(); err != nil {
		t.Fatal(err)
	}
	mustFlushAndClose(t, w)

	segments, _ := filepath.Glob(filepath.Join(dir, wormDir, "*.jsonl"))
	if len(segments) != 2 {
		t.Fatalf("segments = %d, want 2", len(segments))
	}
	if err := os.Remove(segments[0]); err != nil {
		t.Fatal(err)
	}

	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("expected missing segment detection")
	}
	if rep.FirstTampered == nil || rep.FirstTampered.Type != IssueSegmentMissing {
		t.Fatalf("first tampered = %+v, want segment_missing", rep.FirstTampered)
	}
	if rep.AffectedInterval == nil || rep.AffectedInterval.FromSeq != 1 || rep.AffectedInterval.ToSeq != 40 {
		t.Fatalf("affected interval = %+v", rep.AffectedInterval)
	}
}

func TestVerifyWindowOnlyReportsOverlap(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	writeEvents(t, w, 40, time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC), "a")
	mustFlushAndClose(t, w)
	path := filepath.Join(dir, activeFile)
	lines := readFileLines(t, path)
	lines[2] = strings.Replace(lines[2], `"actor":"alice"`, `"actor":"mallory"`, 1)
	writeFileLines(t, path, lines)

	from := time.Date(2026, 11, 11, 10, 0, 20, 0, time.UTC)
	to := time.Date(2026, 11, 11, 10, 0, 39, 0, time.UTC)
	rep, err := Verify(dir, VerifyOptions{From: from, To: to})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("tamper outside window should not fail window verify: %+v", rep.Issues)
	}
	full, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if full.OK {
		t.Fatal("full verify should detect tamper")
	}
}

func TestLegacyMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, activeFile)
	legacy := `{"id":"old-1","time":"2026-11-11T09:00:00Z","actor":"alice","action":"read","resource":"doc/1"}
{"id":"old-2","time":"2026-11-11T09:01:00Z","actor":"bob","action":"read","resource":"doc/2"}
`
	if err := os.WriteFile(path, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	w, err := NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	mustFlushAndClose(t, w)
	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.Checked.Records != 2 {
		t.Fatalf("legacy migration verify failed: ok=%v records=%d issues=%+v", rep.OK, rep.Checked.Records, rep.Issues)
	}
	events, err := ReadAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].ID != "old-1" || events[1].ID != "old-2" {
		t.Fatalf("unexpected events: %+v", events)
	}
}
