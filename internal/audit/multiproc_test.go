package audit

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestMain 支持把测试二进制当成多进程写入子进程使用。
//
// 父测试进程通过环境变量启动多个子进程，每个子进程独立打开同一个数据目录
// 的 Writer，真实地验证跨进程文件锁与全局哈希链的顺序性。
func TestMain(m *testing.M) {
	if dir := os.Getenv("AUDIT_CHILD_DIR"); dir != "" {
		childWriter(dir)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func childWriter(dir string) {
	worker, _ := strconv.Atoi(os.Getenv("AUDIT_CHILD_WORKER"))
	n, _ := strconv.Atoi(os.Getenv("AUDIT_CHILD_N"))
	w, err := NewWriter(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "child new writer:", err)
		os.Exit(2)
	}
	base := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		e := Event{
			ID:       fmt.Sprintf("w%d-%d", worker, i),
			Time:     base.Add(time.Duration(worker*100000+i) * time.Millisecond),
			Actor:    "child",
			Action:   "write",
			Resource: fmt.Sprintf("doc/%d/%d", worker, i),
		}
		if err := w.Write(e); err != nil {
			fmt.Fprintln(os.Stderr, "child write:", err)
			os.Exit(3)
		}
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintln(os.Stderr, "child flush:", err)
		os.Exit(4)
	}
	if err := w.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "child close:", err)
		os.Exit(5)
	}
}

func TestMultiProcessConcurrentWrites(t *testing.T) {
	if testing.Short() {
		t.Skip("skip multi-process test in -short mode")
	}
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const procs = 4
	const per = 500

	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, procs)
	for p := 0; p < procs; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			cmd := exec.Command(exe, "-test.run=^$")
			cmd.Env = append(os.Environ(),
				"AUDIT_CHILD_DIR="+dir,
				fmt.Sprintf("AUDIT_CHILD_WORKER=%d", p),
				fmt.Sprintf("AUDIT_CHILD_N=%d", per),
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				errs <- fmt.Errorf("worker %d: %v: %s", p, err, out)
			}
		}(p)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("multi-process chain broken: %+v", rep.Issues)
	}
	want := int64(procs * per)
	if rep.Checked.Records != want {
		t.Fatalf("records = %d, want %d", rep.Checked.Records, want)
	}
	if rep.Head.Seq != uint64(want) {
		t.Fatalf("head seq = %d, want %d", rep.Head.Seq, want)
	}

	events, err := ReadAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(events)) != want {
		t.Fatalf("ReadAll = %d events, want %d", len(events), want)
	}
	seen := make(map[string]bool, want)
	for _, e := range events {
		if seen[e.ID] {
			t.Fatalf("duplicate event id %q", e.ID)
		}
		seen[e.ID] = true
	}
	t.Logf("multiprocess: procs=%d events=%d elapsed=%s throughput=%.0f/s",
		procs, want, elapsed.Round(time.Millisecond), float64(want)/elapsed.Seconds())
}
