// stress 是多进程并发写入压测工具：启动 P 个独立进程同时写同一个数据目录，
// 结束后校验全局哈希链是否仍然严格有序。
//
//	go run ./cmd/stress -procs 8 -n 5000
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"annot-audit/internal/audit"
)

type childResult struct {
	Worker    int   `json:"worker"`
	Events    int   `json:"events"`
	ElapsedMS int64 `json:"elapsed_ms"`
}

func main() {
	if os.Getenv("AUDIT_STRESS_CHILD") != "" {
		child()
		return
	}
	procs := flag.Int("procs", 8, "number of writer processes")
	n := flag.Int("n", 5000, "events per process")
	dataDir := flag.String("data", "", "data dir (default: temporary dir)")
	batch := flag.Int("batch", 128, "group commit batch size per process")
	seal := flag.Bool("seal", false, "seal each process's active data on exit")
	keep := flag.Bool("keep", false, "keep temporary data dir")
	doVerify := flag.Bool("verify", true, "verify chain after stress")
	flag.Parse()

	dir := *dataDir
	var cleanup func()
	if dir == "" {
		d, err := os.MkdirTemp("", "audit-stress-*")
		if err != nil {
			fatal("temp dir: %v", err)
		}
		dir = d
		if !*keep {
			cleanup = func() { os.RemoveAll(d) }
		}
	}
	if cleanup != nil {
		defer cleanup()
	}

	exe, err := os.Executable()
	if err != nil {
		fatal("executable: %v", err)
	}
	total := *procs * *n
	start := time.Now()

	var wg sync.WaitGroup
	results := make(chan childResult, *procs)
	errs := make(chan error, *procs)
	for p := 0; p < *procs; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			cmd := exec.Command(exe)
			cmd.Env = append(os.Environ(),
				"AUDIT_STRESS_CHILD=1",
				"AUDIT_STRESS_DIR="+dir,
				fmt.Sprintf("AUDIT_STRESS_WORKER=%d", p),
				fmt.Sprintf("AUDIT_STRESS_N=%d", *n),
				fmt.Sprintf("AUDIT_STRESS_BATCH=%d", *batch),
				fmt.Sprintf("AUDIT_STRESS_SEAL=%v", *seal),
			)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				errs <- fmt.Errorf("worker %d: %v: %s", p, err, stderr.String())
				return
			}
			sc := bufio.NewScanner(&stdout)
			for sc.Scan() {
				var r childResult
				if json.Unmarshal(sc.Bytes(), &r) == nil {
					results <- r
				}
			}
		}(p)
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		fatal("%v", err)
	}
	elapsed := time.Since(start)

	var maxChild int64
	var got int
	for r := range results {
		got += r.Events
		if r.ElapsedMS > maxChild {
			maxChild = r.ElapsedMS
		}
	}
	if got != total {
		fatal("child results total=%d, want %d", got, total)
	}

	fmt.Printf("stress: procs=%d per_process=%d total=%d batch=%d seal=%v\n",
		*procs, *n, total, *batch, *seal)
	fmt.Printf("write: wall=%s throughput=%.0f/s slowest_child=%dms\n",
		elapsed.Round(time.Millisecond), float64(total)/elapsed.Seconds(), maxChild)

	if *doVerify {
		vstart := time.Now()
		rep, err := audit.Verify(dir, audit.VerifyOptions{})
		if err != nil {
			fatal("verify: %v", err)
		}
		fmt.Printf("verify: ok=%v records=%d segments=%d elapsed=%dms wall=%s\n",
			rep.OK, rep.Checked.Records, rep.Checked.Segments, rep.ElapsedMS,
			time.Since(vstart).Round(time.Millisecond))
		if !rep.OK {
			for _, is := range rep.Issues {
				fmt.Printf("  issue: type=%s seq=%d file=%s line=%d detail=%s\n",
					is.Type, is.Seq, is.Position.File, is.Position.Line, is.Detail)
			}
			os.Exit(1)
		}
	}
	if !*keep && *dataDir == "" {
		fmt.Printf("data dir: %s (removed)\n", dir)
	} else {
		fmt.Printf("data dir: %s\n", filepath.Clean(dir))
	}
}

func child() {
	dir := os.Getenv("AUDIT_STRESS_DIR")
	worker := atoi(os.Getenv("AUDIT_STRESS_WORKER"))
	n := atoi(os.Getenv("AUDIT_STRESS_N"))
	batch := atoi(os.Getenv("AUDIT_STRESS_BATCH"))
	if batch <= 0 {
		batch = 128
	}
	seal := os.Getenv("AUDIT_STRESS_SEAL") == "true"

	w, err := audit.NewWriterWithOptions(dir, audit.Options{BatchSize: batch})
	if err != nil {
		fatal("child new writer: %v", err)
	}
	base := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	start := time.Now()
	for i := 0; i < n; i++ {
		e := audit.Event{
			ID:       fmt.Sprintf("w%d-%d", worker, i),
			Time:     base.Add(time.Duration(worker*100000+i) * time.Millisecond),
			Actor:    "stress",
			Action:   "write",
			Resource: fmt.Sprintf("doc/%d/%d", worker, i),
		}
		if err := w.Write(e); err != nil {
			fatal("child write: %v", err)
		}
	}
	if err := w.Flush(); err != nil {
		fatal("child flush: %v", err)
	}
	if seal {
		if err := w.Seal(); err != nil {
			fatal("child seal: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		fatal("child close: %v", err)
	}
	el := time.Since(start)
	out, _ := json.Marshal(childResult{Worker: worker, Events: n, ElapsedMS: el.Milliseconds()})
	fmt.Println(string(out))
}

func atoi(s string) int {
	var n int
	fmt.Sscan(s, &n)
	return n
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
