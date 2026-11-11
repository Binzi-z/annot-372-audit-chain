// verify 对审计数据目录做完整性校验，支持任意时间窗口。
//
//	go run ./cmd/verify -data data
//	go run ./cmd/verify -data data -from 2026-11-11T10:00:00Z -to 2026-11-11T11:00:00Z
//	go run ./cmd/verify -data data -json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"annot-audit/internal/audit"
)

func main() {
	dataDir := flag.String("data", "data", "audit data directory")
	from := flag.String("from", "", "window start (RFC3339 / unix seconds / YYYY-MM-DD)")
	to := flag.String("to", "", "window end (RFC3339 / unix seconds / YYYY-MM-DD)")
	asJSON := flag.Bool("json", false, "print JSON report")
	flag.Parse()

	ft, err := parseTime(*from)
	if err != nil {
		fatal("invalid -from: %v", err)
	}
	tt, err := parseTime(*to)
	if err != nil {
		fatal("invalid -to: %v", err)
	}

	rep, err := audit.Verify(*dataDir, audit.VerifyOptions{From: ft, To: tt})
	if err != nil {
		fatal("verify: %v", err)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		printHuman(rep)
	}
	if !rep.OK {
		os.Exit(1)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}

func parseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0).UTC(), nil
	}
	for _, layout := range []string{
		time.RFC3339Nano, time.RFC3339,
		"2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized time %q", s)
}

func printHuman(rep *audit.Report) {
	fmt.Printf("verify: data=%s\n", rep.DataDir)
	if rep.Window != nil {
		fmt.Printf("window: %s .. %s\n", windowBound(rep.Window.From), windowBound(rep.Window.To))
	}
	fmt.Printf("checked: records=%d in_window=%d segments=%d seq=%d..%d elapsed=%dms\n",
		rep.Checked.Records, rep.Checked.RecordsInWindow, rep.Checked.Segments,
		rep.Checked.FromSeq, rep.Checked.ToSeq, rep.ElapsedMS)
	fmt.Printf("head: seq=%d hash=%s\n", rep.Head.Seq, rep.Head.Hash)
	if rep.OK {
		fmt.Println("OK: audit chain is intact")
		return
	}
	fmt.Printf("TAMPERED: %d issue(s)\n", len(rep.Issues))
	if rep.FirstTampered != nil {
		i := rep.FirstTampered
		fmt.Printf("first_tampered: type=%s seq=%d file=%s line=%d offset=%d\n",
			i.Type, i.Seq, i.Position.File, i.Position.Line, i.Position.Offset)
		if i.Detail != "" {
			fmt.Printf("  detail: %s\n", i.Detail)
		}
		if i.Expected != "" || i.Actual != "" {
			fmt.Printf("  expected=%s actual=%s\n", i.Expected, i.Actual)
		}
	}
	if rep.AffectedInterval != nil {
		fmt.Printf("affected_interval: seq %d..%d\n",
			rep.AffectedInterval.FromSeq, rep.AffectedInterval.ToSeq)
	}
	for n, i := range rep.Issues {
		if n >= 20 {
			fmt.Printf("... and %d more issue(s) (use -json for full report)\n", len(rep.Issues)-n)
			break
		}
		fmt.Printf("issue[%d]: type=%s seq=%d file=%s line=%d", n, i.Type, i.Seq, i.Position.File, i.Position.Line)
		if i.Affected != nil {
			fmt.Printf(" affected=%d..%d", i.Affected.FromSeq, i.Affected.ToSeq)
		}
		if i.Detail != "" {
			fmt.Printf(" detail=%q", i.Detail)
		}
		fmt.Println()
	}
}

func windowBound(t *time.Time) string {
	if t == nil {
		return "-inf"
	}
	return t.UTC().Format(time.RFC3339Nano)
}
