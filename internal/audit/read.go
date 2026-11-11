package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ReadAll 读取数据目录中的全部事件（活跃文件 + 所有已封存 WORM 段），
// 按链序号排序返回。为兼容旧版数据，也接受没有链字段的纯 Event 行。
func ReadAll(dir string) ([]Event, error) {
	flushRegistered(dir)

	var files []string
	active := filepath.Join(dir, activeFile)
	if _, err := os.Stat(active); err == nil {
		files = append(files, active)
	}
	sealed, err := filepath.Glob(filepath.Join(dir, wormDir, "*.jsonl"))
	if err != nil {
		return nil, err
	}
	files = append(files, sealed...)

	type item struct {
		seq   uint64
		order int
		event Event
	}
	var items []item
	order := 0
	chained := false
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		br := bufio.NewReaderSize(f, 1<<20)
		for {
			line, readErr := br.ReadBytes('\n')
			body := trimLine(trimBOM(line))
			if len(body) > 0 && len(strings.TrimSpace(string(body))) > 0 {
				var dr diskRecord
				if err := json.Unmarshal(body, &dr); err == nil && dr.Seq > 0 && dr.Hash != "" {
					var e Event
					if err := json.Unmarshal(dr.Event, &e); err != nil {
						f.Close()
						return nil, err
					}
					chained = true
					items = append(items, item{seq: dr.Seq, order: order, event: e})
					order++
				} else {
					var e Event
					if err := json.Unmarshal(body, &e); err != nil {
						f.Close()
						return nil, err
					}
					items = append(items, item{order: order, event: e})
					order++
				}
			}
			if readErr != nil {
				break
			}
		}
		f.Close()
	}

	if chained {
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].seq == 0 || items[j].seq == 0 {
				return items[i].order < items[j].order
			}
			return items[i].seq < items[j].seq
		})
	}
	out := make([]Event, len(items))
	for i := range items {
		out[i] = items[i].event
	}
	return out, nil
}
