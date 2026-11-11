// Package audit 提供最基础的审计事件写入能力。
//
// 当前实现的边界（刻意保持朴素，留给任务去扩展）：
//   - 每条事件只是顺序追加到 events.jsonl，事件之间没有任何关联；
//   - 没有哈希、没有签名、没有校验；
//   - 只有进程内互斥，多进程同时写不保证顺序；
//   - 轮转按文件大小切分，切分后不可追溯。
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event 是一条审计事件。
type Event struct {
	ID       string                 `json:"id"`
	Time     time.Time              `json:"time"`
	Actor    string                 `json:"actor"`
	Action   string                 `json:"action"`
	Resource string                 `json:"resource"`
	Extra    map[string]interface{} `json:"extra,omitempty"`
}

// Writer 把事件追加写入目录下的 events.jsonl。
type Writer struct {
	mu   sync.Mutex
	f    *os.File
	path string
	n    int64
}

// NewWriter 打开（或创建）dir/events.jsonl 用于追加。
func NewWriter(dir string) (*Writer, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	path := filepath.Join(dir, "events.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open events file: %w", err)
	}
	return &Writer{f: f, path: path}, nil
}

// Write 追加一条事件。调用方负责填好 ID 与 Time。
func (w *Writer) Write(e Event) error {
	if e.ID == "" {
		return fmt.Errorf("event id is required")
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	buf, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	buf = append(buf, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.f.Write(buf); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	w.n++
	return nil
}

// Count 返回本进程写入的事件数。
func (w *Writer) Count() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.n
}

// Path 返回落盘文件路径。
func (w *Writer) Path() string { return w.path }

// Close 关闭文件句柄。
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}

// ReadAll 读取 dir/events.jsonl 的全部事件（测试与查询接口用）。
func ReadAll(dir string) ([]Event, error) {
	path := filepath.Join(dir, "events.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Event
	for _, line := range splitLines(raw) {
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("corrupt line: %w", err)
		}
		out = append(out, e)
	}
	return out, nil
}

func splitLines(b []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			lines = append(lines, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		lines = append(lines, b[start:])
	}
	return lines
}
