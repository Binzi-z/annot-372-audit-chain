package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// corruptRecordError 便于调用方拿到出错的准确行号与字节偏移。
type corruptRecordError struct {
	Line   int
	Offset int64
	Path   string
	Err    error
}

func (e *corruptRecordError) Error() string {
	return fmt.Sprintf("%s:%d: corrupt record: %v", e.Path, e.Line, e.Err)
}

func (e *corruptRecordError) Unwrap() error { return e.Err }

// scanFile 顺序扫描一个审计文件，回调每条记录。它同时计算整个文件的
// SHA-256 和字节数，供封存/校验时与 SQLite 元数据比对。
func scanFile(path string, fn func(raw []byte, dr *diskRecord, lineNo int, offset int64) error) (shaHex string, size int64, count int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, 0, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", 0, 0, err
	}
	fh := sha256.New()
	reader := bufio.NewReaderSize(f, 1<<20)
	var offset int64
	var lineNo int
	for {
		raw, readErr := reader.ReadBytes('\n')
		if len(raw) > 0 {
			lineNo++
			fh.Write(raw)
			start := offset
			offset += int64(len(raw))
			body := trimLine(raw)
			if len(body) == 0 {
				if readErr == io.EOF {
					break
				}
				continue
			}
			var dr diskRecord
			if err := json.Unmarshal(body, &dr); err != nil {
				return "", 0, 0, &corruptRecordError{Line: lineNo, Offset: start, Path: path, Err: err}
			}
			count++
			if err := fn(raw, &dr, lineNo, start); err != nil {
				return "", 0, 0, err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", 0, 0, readErr
		}
	}
	return hex.EncodeToString(fh.Sum(nil)), info.Size(), count, nil
}

func trimLine(raw []byte) []byte {
	end := len(raw)
	for end > 0 && (raw[end-1] == '\n' || raw[end-1] == '\r') {
		end--
	}
	return raw[:end]
}
