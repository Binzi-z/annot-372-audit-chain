// gen 生成大量审计事件，用于吞吐与 verify 性能压测。
//
//	go run ./cmd/gen -n 1000000 -data ./tmpdata -seal -verify
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"annot-audit/internal/audit"
)

func main() {
	n := flag.Int("n", 1000000, "number of events")
	dataDir := flag.String("data", "data", "data directory")
	batch := flag.Int("batch", 512, "group commit batch size")
	seal := flag.Bool("seal", false, "seal active segment at the end")
	doVerify := flag.Bool("verify", false, "run verify after generation")
	hours := flag.Int("hours", 1, "spread events over this many hourly segments")
	flag.Parse()

	w, err := audit.NewWriterWithOptions(*dataDir, audit.Options{BatchSize: *batch})
	if err != nil {
		fatal("new writer: %v", err)
	}
	base := time.Now().UTC().Truncate(time.Hour)
	start := time.Now()
	for i := 0; i < *n; i++ {
		h := 0
		if *hours > 1 {
			h = i % *hours
		}
		e := audit.Event{
			ID:       fmt.Sprintf("gen-%d", i),
			Time:     base.Add(time.Duration(h)*time.Hour + time.Duration(i%3600)*time.Second),
			Actor:    fmt.Sprintf("user-%d", i%100),
			Action:   "read",
			Resource: fmt.Sprintf("doc/%d", i),
		}
		if err := w.Write(e); err != nil {
			fatal("write: %v", err)
		}
	}
	if err := w.Flush(); err != nil {
		fatal("flush: %v", err)
	}
	if *seal {
		if err := w.Seal(); err != nil {
			fatal("seal: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		fatal("close: %v", err)
	}
	el := time.Since(start)
	fmt.Printf("generated: n=%d elapsed=%s throughput=%.0f/s\n",
		*n, el.Round(time.Millisecond), float64(*n)/el.Seconds())

	if *doVerify {
		vstart := time.Now()
		rep, err := audit.Verify(*dataDir, audit.VerifyOptions{})
		if err != nil {
			fatal("verify: %v", err)
		}
		fmt.Printf("verify: ok=%v records=%d segments=%d elapsed=%dms (wall %s)\n",
			rep.OK, rep.Checked.Records, rep.Checked.Segments, rep.ElapsedMS, time.Since(vstart).Round(time.Millisecond))
		if !rep.OK {
			for _, is := range rep.Issues {
				fmt.Printf("  issue: type=%s seq=%d detail=%s\n", is.Type, is.Seq, is.Detail)
			}
			os.Exit(1)
		}
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
