package audit

import (
	"fmt"
	"testing"
)

// BenchmarkWrite 单进程写入吞吐基线。任务要求改造后吞吐下降不超过 10%，
// 用这个基准做前后对比：
//
//	go test ./internal/audit -bench=BenchmarkWrite -benchtime=3s -run=^$ > before.txt
//	go test ./internal/audit -bench=BenchmarkWrite -benchtime=3s -run=^$ > after.txt
func BenchmarkWrite(b *testing.B) {
	w, err := NewWriter(b.TempDir())
	if err != nil {
		b.Fatalf("new writer: %v", err)
	}
	defer w.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := w.Write(Event{
			ID:       fmt.Sprintf("bench-%d", i),
			Actor:    "bench",
			Action:   "write",
			Resource: "doc/bench",
		}); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
}
