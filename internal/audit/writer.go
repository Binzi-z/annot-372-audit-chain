// Package audit 提供带哈希链、按小时封存 WORM 的审计日志。
//
// 设计要点：
//   - 每条记录包含 seq / prev / hash，hash = SHA256(domain||prev||seq||event)；
//   - 写入采用组提交（group commit）：应用侧先进入进程内缓冲，按批次持跨进程
//     文件锁分配序号、计算哈希并顺序落盘，多进程共享同一条链；
//   - 每跨过一个小时（或显式调用 Seal）把当前活跃文件封存为 WORM 段，
//     计算 Merkle root 与文件 SHA-256，链头与段元数据写入 SQLite；
//   - verify 能检测删除、重排、内容修改与整段缺失，并输出取证报告。
package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event 是一条审计事件（对外接口保持不变）。
type Event struct {
	ID       string                 `json:"id"`
	Time     time.Time              `json:"time"`
	Actor    string                 `json:"actor"`
	Action   string                 `json:"action"`
	Resource string                 `json:"resource"`
	Extra    map[string]interface{} `json:"extra,omitempty"`
}

const (
	defaultBatchSize     = 128
	defaultFlushInterval = 10 * time.Millisecond
	defaultSealInterval  = 30 * time.Second
)

// Options 控制写入行为。零值表示使用默认值。
type Options struct {
	// BatchSize 每积累多少条记录触发一次组提交。
	BatchSize int
	// FlushInterval 最长多久把缓冲刷到磁盘（0 表示默认值）。
	FlushInterval time.Duration
	// SealInterval 巡检小时边界的间隔。
	SealInterval time.Duration
	// WORMImmutable 封存后把文件置为 0444（生产环境建议开启）。
	WORMImmutable bool
	// SealOnClose 在 Close 时封存当前活跃段（服务优雅退出时建议开启）。
	SealOnClose bool
}

type pendingRec struct {
	ts      time.Time
	payload []byte
}

// Writer 是并发安全的审计写入器，可被同目录的多个进程同时使用。
type Writer struct {
	dir  string
	opts Options

	mu      sync.Mutex
	pending []pendingRec
	flushed int64
	lastErr error
	closed  bool

	flushMu sync.Mutex

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	extLock *fileLock
	store   *store

	// 持久化的活跃文件句柄，避免每次组提交都 open/close（Windows 上开销很大）。
	activeF *os.File
	activeW *bufio.Writer

	// 活跃段状态。受 flushMu + extLock 保护（写入路径之外不读取）。
	segHour      time.Time
	actFirstSeq  uint64
	actFirstPrev string
	actFirstTime time.Time
	actStarted   time.Time
	actCount     int64
	head         chainHead
}

// NewWriter 打开（或创建）dir 下的审计写入器。
func NewWriter(dir string) (*Writer, error) {
	return NewWriterWithOptions(dir, Options{})
}

// NewWriterWithOptions 打开写入器并覆盖默认选项。
func NewWriterWithOptions(dir string, opts Options) (*Writer, error) {
	if opts.BatchSize <= 0 {
		opts.BatchSize = defaultBatchSize
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = defaultFlushInterval
	}
	if opts.SealInterval <= 0 {
		opts.SealInterval = defaultSealInterval
	}
	if err := os.MkdirAll(filepath.Join(dir, wormDir), 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	lock, err := openFileLock(filepath.Join(dir, lockFile))
	if err != nil {
		return nil, fmt.Errorf("open lock: %w", err)
	}
	if err := lock.Lock(); err != nil {
		lock.Close()
		return nil, fmt.Errorf("acquire init lock: %w", err)
	}
	st, err := openStore(dir)
	if err != nil {
		lock.Unlock()
		lock.Close()
		return nil, err
	}
	w := &Writer{
		dir:     dir,
		opts:    opts,
		stopCh:  make(chan struct{}),
		extLock: lock,
		store:   st,
	}
	if err := w.initLocked(); err != nil {
		lock.Unlock()
		lock.Close()
		st.Close()
		return nil, err
	}
	if err := w.openActiveWriter(); err != nil {
		lock.Unlock()
		lock.Close()
		st.Close()
		return nil, err
	}
	lock.Unlock()

	w.wg.Add(1)
	go w.background()
	registerWriter(w)
	return w, nil
}

func (w *Writer) activePath() string {
	return filepath.Join(w.dir, activeFile)
}

// truncateActive 把活跃文件清空并重新打开写句柄。Windows 上 O_APPEND 句柄
// 没有 FILE_WRITE_DATA 权限，不能直接 Truncate，因此关闭后按路径截断。
func (w *Writer) truncateActive() error {
	if w.activeW != nil {
		if err := w.activeW.Flush(); err != nil {
			return err
		}
	}
	if w.activeF != nil {
		if err := w.activeF.Close(); err != nil {
			return err
		}
		w.activeF = nil
		w.activeW = nil
	}
	if err := os.Truncate(w.activePath(), 0); err != nil {
		return err
	}
	return w.openActiveWriter()
}

// openActiveWriter 打开持久化的活跃文件句柄。Seal 采用“复制到 WORM + 截断
// 活跃文件”的方式，因此句柄可以一直复用，路径保持稳定。
func (w *Writer) openActiveWriter() error {
	if w.activeF != nil {
		return nil
	}
	f, err := os.OpenFile(w.activePath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open active file: %w", err)
	}
	w.activeF = f
	w.activeW = bufio.NewWriterSize(f, 1<<20)
	return nil
}

func (w *Writer) wormPath(name string) string {
	return filepath.Join(w.dir, wormDir, name)
}

func (w *Writer) initLocked() error {
	if err := w.migrateLegacyLocked(); err != nil {
		return err
	}
	if err := w.dedupeActiveLocked(); err != nil {
		return err
	}
	return w.recoverLocked()
}

// dedupeActiveLocked 处理封存崩溃窗口：WORM 段已落库但活跃文件尚未截断时，
// 截掉活跃文件中已经封存的前缀，避免重启后出现重复序号。
func (w *Writer) dedupeActiveLocked() error {
	segments, err := w.store.listSegments()
	if err != nil || len(segments) == 0 {
		return err
	}
	maxSealed := segments[len(segments)-1].LastSeq
	path := w.activePath()
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Size() == 0 {
		return nil
	}
	first, err := readFirstRecord(path)
	if err != nil {
		return err
	}
	if first.Seq > maxSealed {
		return nil
	}
	var truncAt int64 = -1
	_, _, _, err = scanFile(path, func(raw []byte, dr *diskRecord, line int, offset int64) error {
		if dr.Seq == maxSealed {
			truncAt = offset + int64(len(raw))
		}
		return nil
	})
	if err != nil {
		return err
	}
	if truncAt >= 0 {
		if err := os.Truncate(path, truncAt); err != nil {
			return err
		}
	}
	return nil
}

// migrateLegacyLocked 把旧版 events.jsonl（纯 Event 行、无链字段）就地
// 改写为带哈希链的记录，保证平滑升级，旧数据也纳入完整性保护。
func (w *Writer) migrateLegacyLocked() error {
	path := w.activePath()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	first := firstNonEmptyLine(raw)
	if bytes.Contains(first, []byte(`"seq":`)) {
		return nil // 已经是链式记录
	}
	head, err := w.store.loadHead()
	if err != nil {
		return err
	}
	var out bytes.Buffer
	seq := head.Seq
	prev := head.Hash
	for _, line := range splitLines(raw) {
		body := trimLine(trimBOM(line))
		if len(bytes.TrimSpace(body)) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(body, &e); err != nil {
			return fmt.Errorf("migrate legacy line: %w", err)
		}
		if e.Time.IsZero() {
			e.Time = time.Now().UTC()
		}
		e.Time = e.Time.UTC()
		payload, err := json.Marshal(e)
		if err != nil {
			return err
		}
		seq++
		h := chainHash(prev, seq, e.Time, payload)
		out.Write(encodeRecord(seq, prev, h, e.Time, payload))
		prev = h
	}
	tmp := path + ".migrate"
	if err := os.WriteFile(tmp, out.Bytes(), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	head = chainHead{Seq: seq, Hash: prev}
	if err := w.store.saveHead(head); err != nil {
		return err
	}
	w.head = head
	return nil
}

// recoverLocked 修复崩溃留下的半行、并把 SQLite 链头与磁盘实际内容对齐。
func (w *Writer) recoverLocked() error {
	path := w.activePath()
	if err := repairPartialTail(path); err != nil {
		return err
	}
	head, err := w.store.loadHead()
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			w.resetActive()
			return w.store.clearActive()
		}
		return err
	}
	if info.Size() == 0 {
		w.resetActive()
		return w.store.clearActive()
	}
	first, err := readFirstRecord(path)
	if err != nil {
		return err
	}
	last, err := readLastRecord(path)
	if err != nil {
		return err
	}
	if last.Seq > head.Seq {
		head = chainHead{Seq: last.Seq, Hash: last.Hash}
	}
	act := &activeMeta{
		File:      activeFile,
		Hour:      fmtTime(first.Time.Truncate(time.Hour)),
		FirstSeq:  first.Seq,
		FirstPrev: first.Prev,
		FirstTime: fmtTime(first.Time),
		LastSeq:   last.Seq,
		LastHash:  last.Hash,
		Count:     int64(last.Seq-first.Seq) + 1,
		StartedAt: fmtTime(first.Time),
	}
	if prev, err := w.store.loadActive(); err != nil {
		return err
	} else if prev != nil && prev.FirstSeq == first.Seq && prev.FirstPrev == first.Prev && prev.LastSeq <= last.Seq {
		act.Count = prev.Count + int64(last.Seq-prev.LastSeq)
		act.StartedAt = prev.StartedAt
	}
	if err := w.store.saveState(head, act); err != nil {
		return err
	}
	w.head = head
	w.applyActive(act)
	return nil
}

func (w *Writer) resetActive() {
	w.segHour = time.Time{}
	w.actFirstSeq = 0
	w.actFirstPrev = ""
	w.actFirstTime = time.Time{}
	w.actStarted = time.Time{}
	w.actCount = 0
}

func (w *Writer) applyActive(a *activeMeta) {
	if a == nil {
		w.resetActive()
		return
	}
	w.actFirstSeq = a.FirstSeq
	w.actFirstPrev = a.FirstPrev
	w.actFirstTime, _ = time.Parse(time.RFC3339Nano, a.FirstTime)
	w.actStarted, _ = time.Parse(time.RFC3339Nano, a.StartedAt)
	w.segHour, _ = time.Parse(time.RFC3339Nano, a.Hour)
	w.actCount = a.Count
}

func (w *Writer) activeMetaFor(head chainHead) *activeMeta {
	if w.actCount == 0 {
		return nil
	}
	return &activeMeta{
		File:      activeFile,
		Hour:      fmtTime(w.segHour),
		FirstSeq:  w.actFirstSeq,
		FirstPrev: w.actFirstPrev,
		FirstTime: fmtTime(w.actFirstTime),
		LastSeq:   head.Seq,
		LastHash:  head.Hash,
		Count:     w.actCount,
		StartedAt: fmtTime(w.actStarted),
	}
}

// Write 追加一条事件。调用方负责填好 ID；Time 为空时使用当前 UTC 时间。
//
// 事件先进入进程内缓冲，返回 nil 表示已受理。缓冲区达到 BatchSize 时同步
// 组提交，否则由后台定时器在 FlushInterval 内落盘。需要强可见性时调用 Flush。
func (w *Writer) Write(e Event) error {
	if e.ID == "" {
		return fmt.Errorf("event id is required")
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.Time = e.Time.UTC()
	payload, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return fmt.Errorf("writer is closed")
	}
	w.pending = append(w.pending, pendingRec{ts: e.Time, payload: payload})
	n := len(w.pending)
	w.mu.Unlock()
	if n >= w.opts.BatchSize {
		return w.Flush()
	}
	return nil
}

// Flush 把当前进程缓冲的所有事件落盘（必要时与其他进程组提交）。
func (w *Writer) Flush() error {
	w.flushMu.Lock()
	defer w.flushMu.Unlock()
	return w.flushLocked()
}

func (w *Writer) flushLocked() error {
	for {
		w.mu.Lock()
		if len(w.pending) == 0 {
			w.mu.Unlock()
			return nil
		}
		batch := w.pending
		w.pending = nil
		w.mu.Unlock()

		if err := w.writeBatch(batch); err != nil {
			w.mu.Lock()
			w.pending = append(batch, w.pending...)
			w.lastErr = err
			w.mu.Unlock()
			return err
		}
		w.mu.Lock()
		w.flushed += int64(len(batch))
		w.mu.Unlock()
	}
}

func (w *Writer) writeBatch(batch []pendingRec) error {
	w.extLock.Lock()
	defer w.extLock.Unlock()

	head, err := w.store.loadHead()
	if err != nil {
		return err
	}
	act, err := w.store.loadActive()
	if err != nil {
		return err
	}
	w.applyActive(act)

	if err := w.openActiveWriter(); err != nil {
		return err
	}

	for i := range batch {
		rec := batch[i]
		hour := rec.ts.Truncate(time.Hour)
		if w.segHour.IsZero() {
			w.segHour = hour
			w.actStarted = time.Now().UTC()
		} else if hour.After(w.segHour) {
			if err := w.activeW.Flush(); err != nil {
				return err
			}
			if err := w.sealLocked(); err != nil {
				return err
			}
			w.segHour = hour
			w.actStarted = time.Now().UTC()
		}
		seq := head.Seq + 1
		prev := head.Hash
		hash := chainHash(prev, seq, rec.ts, rec.payload)
		if _, err := w.activeW.Write(encodeRecord(seq, prev, hash, rec.ts, rec.payload)); err != nil {
			return err
		}
		if w.actFirstSeq == 0 {
			w.actFirstSeq = seq
			w.actFirstPrev = prev
			w.actFirstTime = rec.ts
		}
		w.actCount++
		head = chainHead{Seq: seq, Hash: hash}
	}
	if err := w.activeW.Flush(); err != nil {
		return err
	}
	if err := w.store.saveState(head, w.activeMetaFor(head)); err != nil {
		return err
	}
	w.head = head
	return nil
}

// Seal 把当前活跃文件封存为一个 WORM 段（仅在某个小时结束后需要）。
func (w *Writer) Seal() error {
	w.flushMu.Lock()
	defer w.flushMu.Unlock()
	if err := w.flushLocked(); err != nil {
		return err
	}
	w.extLock.Lock()
	defer w.extLock.Unlock()
	return w.sealLocked()
}

func (w *Writer) sealLocked() error {
	if w.activeW != nil {
		if err := w.activeW.Flush(); err != nil {
			return err
		}
	}
	path := w.activePath()
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			w.resetActive()
			return w.store.clearActive()
		}
		return err
	}
	if info.Size() == 0 {
		w.resetActive()
		return w.store.clearActive()
	}

	var (
		leaves    [][32]byte
		firstSeq  uint64
		lastSeq   uint64
		firstPrev string
		lastHash  string
		firstTime time.Time
		lastTime  time.Time
		expSeq    uint64
		expPrev   string
	)
	fileSHA, size, count, err := scanFile(path, func(raw []byte, dr *diskRecord, lineNo int, offset int64) error {
		if firstSeq == 0 {
			firstSeq = dr.Seq
			firstPrev = dr.Prev
			firstTime = dr.Time
			expSeq = dr.Seq
			expPrev = dr.Prev
		}
		if dr.Seq != expSeq {
			return fmt.Errorf("seal: %s:%d seq %d, want %d", path, lineNo, dr.Seq, expSeq)
		}
		if dr.Prev != expPrev {
			return fmt.Errorf("seal: %s:%d prev mismatch", path, lineNo)
		}
		if got := chainHash(dr.Prev, dr.Seq, dr.Time, dr.Event); got != dr.Hash {
			return fmt.Errorf("seal: %s:%d hash mismatch", path, lineNo)
		}
		leaf, err := decodeHash(dr.Hash)
		if err != nil {
			return fmt.Errorf("seal: %s:%d %w", path, lineNo, err)
		}
		leaves = append(leaves, leaf)
		lastSeq = dr.Seq
		lastHash = dr.Hash
		lastTime = dr.Time
		expSeq = dr.Seq + 1
		expPrev = dr.Hash
		return nil
	})
	if err != nil {
		return err
	}
	if count == 0 {
		if err := w.truncateActive(); err != nil {
			return err
		}
		w.resetActive()
		return w.store.clearActive()
	}

	hour := w.segHour
	if hour.IsZero() {
		hour = firstTime.Truncate(time.Hour)
	}
	id := fmt.Sprintf("seg-%s-%d-%d.jsonl", hour.UTC().Format("20060102T150405Z"), firstSeq, lastSeq)
	rel := filepath.ToSlash(filepath.Join(wormDir, id))
	dst := w.wormPath(id)
	// 复制 → fsync → 落库 → 截断活跃文件。活跃文件句柄全程持有，避免
	// Windows 上 rename 打开文件的限制；WORM 段一旦创建就不再修改。
	if err := copyFileExclusive(path, dst); err != nil {
		return fmt.Errorf("seal copy: %w", err)
	}
	meta := segmentMeta{
		ID:         id,
		Path:       rel,
		Hour:       fmtTime(hour),
		FirstSeq:   firstSeq,
		LastSeq:    lastSeq,
		FirstPrev:  firstPrev,
		LastHash:   lastHash,
		FirstTime:  fmtTime(firstTime),
		LastTime:   fmtTime(lastTime),
		Count:      count,
		MerkleRoot: merkleRoot(leaves),
		FileSHA256: fileSHA,
		Size:       size,
		SealedAt:   fmtTime(time.Now()),
	}
	if err := writeManifest(dst+".manifest.json", meta); err != nil {
		return err
	}
	if w.opts.WORMImmutable {
		_ = os.Chmod(dst, 0o444)
		_ = os.Chmod(dst+".manifest.json", 0o444)
	}
	if err := w.store.insertSegment(meta); err != nil {
		return err
	}
	if err := w.store.saveState(chainHead{Seq: lastSeq, Hash: lastHash}, nil); err != nil {
		return err
	}
	if err := w.truncateActive(); err != nil {
		return fmt.Errorf("truncate active after seal: %w", err)
	}
	w.head = chainHead{Seq: lastSeq, Hash: lastHash}
	w.resetActive()
	return nil
}

// copyFileExclusive 以“只新建、不覆盖”的方式把活跃文件复制进 WORM 目录。
func copyFileExclusive(src, dst string) error {
	r, err := os.Open(src)
	if err != nil {
		return err
	}
	defer r.Close()
	wf, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(wf, r); err != nil {
		wf.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := wf.Sync(); err != nil {
		wf.Close()
		_ = os.Remove(dst)
		return err
	}
	return wf.Close()
}

func writeManifest(path string, m segmentMeta) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o644)
}

func (w *Writer) background() {
	defer w.wg.Done()
	flushTicker := time.NewTicker(w.opts.FlushInterval)
	sealTicker := time.NewTicker(w.opts.SealInterval)
	defer flushTicker.Stop()
	defer sealTicker.Stop()
	for {
		select {
		case <-w.stopCh:
			return
		case <-flushTicker.C:
			_ = w.Flush()
		case <-sealTicker.C:
			w.maybeSeal()
		}
	}
}

func (w *Writer) maybeSeal() {
	w.flushMu.Lock()
	defer w.flushMu.Unlock()
	if err := w.flushLocked(); err != nil {
		return
	}
	w.extLock.Lock()
	defer w.extLock.Unlock()
	act, err := w.store.loadActive()
	if err != nil || act == nil {
		return
	}
	hour, err := time.Parse(time.RFC3339Nano, act.Hour)
	if err != nil {
		return
	}
	if time.Now().UTC().Truncate(time.Hour).After(hour) {
		_ = w.sealLocked()
	}
}

// Count 返回本进程已受理的事件数（含尚未落盘的缓冲）。
func (w *Writer) Count() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushed + int64(len(w.pending))
}

// Path 返回活跃文件路径。
func (w *Writer) Path() string { return w.activePath() }

// LastError 返回最近一次后台刷盘错误（若有）。
func (w *Writer) LastError() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastErr
}

// Close 停止后台任务、刷盘并释放资源。不会封存当前小时（未结束的小时继续
// 保持活跃；需要立即封存请显式调用 Seal）。
func (w *Writer) Close() error {
	w.stopOnce.Do(func() { close(w.stopCh) })
	w.wg.Wait()
	unregisterWriter(w)

	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
	flushErr := w.Flush()

	var firstErr error
	if flushErr != nil {
		firstErr = flushErr
	}
	if w.opts.SealOnClose && firstErr == nil {
		if err := w.Seal(); err != nil {
			firstErr = err
		}
	}
	if w.activeW != nil {
		if err := w.activeW.Flush(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if w.activeF != nil {
		if err := w.activeF.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		w.activeF = nil
		w.activeW = nil
	}
	if err := w.store.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := w.extLock.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// ---- 文件读取小工具（写入/恢复共用） ----

func firstNonEmptyLine(raw []byte) []byte {
	for _, line := range splitLines(raw) {
		b := bytes.TrimSpace(line)
		if len(b) > 0 {
			return b
		}
	}
	return nil
}

func trimBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
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

func readFirstRecord(path string) (*diskRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 1<<20)
	for {
		line, err := br.ReadBytes('\n')
		body := trimLine(trimBOM(line))
		if len(bytes.TrimSpace(body)) > 0 {
			var dr diskRecord
			if err := json.Unmarshal(body, &dr); err != nil {
				return nil, err
			}
			return &dr, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func readLastRecord(path string) (*diskRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	if size == 0 {
		return nil, fmt.Errorf("empty audit file")
	}
	// 从文件尾部逐步扩大窗口，找到最后两行。
	win := int64(4096)
	for {
		if win > size {
			win = size
		}
		buf := make([]byte, win)
		if _, err := f.ReadAt(buf, size-win); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		// 去掉末尾换行后，找上一处换行。
		end := len(buf)
		for end > 0 && (buf[end-1] == '\n' || buf[end-1] == '\r') {
			end--
		}
		start := end - 1
		for start >= 0 && buf[start] != '\n' {
			start--
		}
		line := buf[start+1 : end]
		if len(bytes.TrimSpace(line)) > 0 {
			var dr diskRecord
			if err := json.Unmarshal(line, &dr); err == nil {
				return &dr, nil
			}
		}
		if win == size {
			return nil, fmt.Errorf("no valid last record in %s", path)
		}
		win *= 2
	}
}

// repairPartialTail 截掉崩溃时写了一半的最后一行（无换行结尾）。
func repairPartialTail(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	if size == 0 {
		return nil
	}
	last := make([]byte, 1)
	if _, err := f.ReadAt(last, size-1); err != nil {
		return err
	}
	if last[0] == '\n' {
		return nil
	}
	win := int64(4096)
	for {
		if win > size {
			win = size
		}
		buf := make([]byte, win)
		if _, err := f.ReadAt(buf, size-win); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		for i := len(buf) - 1; i >= 0; i-- {
			if buf[i] == '\n' {
				return f.Truncate(size - win + int64(i) + 1)
			}
		}
		if win == size {
			return f.Truncate(0)
		}
		win *= 2
	}
}

// ---- 进程内 Writer 注册表：让 ReadAll 能看到尚未刷盘的数据 ----

var (
	registryMu sync.Mutex
	registry   = map[string][]*Writer{}
)

func registerWriter(w *Writer) {
	registryMu.Lock()
	registry[w.dir] = append(registry[w.dir], w)
	registryMu.Unlock()
}

func unregisterWriter(w *Writer) {
	registryMu.Lock()
	list := registry[w.dir]
	for i, x := range list {
		if x == w {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(registry, w.dir)
	} else {
		registry[w.dir] = list
	}
	registryMu.Unlock()
}

func flushRegistered(dir string) {
	registryMu.Lock()
	list := append([]*Writer(nil), registry[dir]...)
	registryMu.Unlock()
	for _, w := range list {
		_ = w.Flush()
	}
}
