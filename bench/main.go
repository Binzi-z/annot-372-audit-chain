// loadgen 并发写入压测：模拟多个客户端同时打审计接口。
//
//	go run ./bench -n 2000 -c 32        # 2000 条事件，32 并发
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var (
	url   = flag.String("url", "http://127.0.0.1:8099/events", "audit endpoint")
	total = flag.Int("n", 1000, "total events")
	conc  = flag.Int("c", 16, "concurrency")
)

func main() {
	flag.Parse()

	var ok, fail int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, *conc)
	start := time.Now()

	for i := 0; i < *total; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()

			body, _ := json.Marshal(map[string]any{
				"id":       fmt.Sprintf("load-%d", i),
				"actor":    "loadgen",
				"action":   "write",
				"resource": "doc/load",
			})
			resp, err := http.Post(*url, "application/json", bytes.NewReader(body))
			if err != nil {
				atomic.AddInt64(&fail, 1)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode/100 != 2 {
				atomic.AddInt64(&fail, 1)
				return
			}
			atomic.AddInt64(&ok, 1)
		}(i)
	}
	wg.Wait()

	el := time.Since(start)
	fmt.Printf("total=%d ok=%d fail=%d elapsed=%s throughput=%.0f/s\n",
		*total, ok, fail, el.Round(time.Millisecond), float64(ok)/el.Seconds())
	if fail > 0 {
		os.Exit(1)
	}
}
