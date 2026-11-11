package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// 问题类型。
const (
	IssueContentModified     = "content_modified"
	IssueRecordDeletion      = "record_deleted"
	IssueRecordReorder       = "record_reordered"
	IssueDuplicateSeq        = "duplicate_seq"
	IssueChainBreak          = "hash_chain_broken"
	IssueCorruptRecord       = "corrupt_record"
	IssueSegmentMissing      = "segment_missing"
	IssueMetadataMismatch    = "metadata_mismatch"
	IssueUnregisteredSegment = "unregistered_segment"
)

// VerifyOptions 指定校验的时间窗口；零值表示不限。
type VerifyOptions struct {
	From time.Time
	To   time.Time
}

// TimeWindow 是回显的查询窗口。
type TimeWindow struct {
	From *time.Time `json:"from,omitempty"`
	To   *time.Time `json:"to,omitempty"`
}

// Position 指出问题在磁盘上的精确位置。
type Position struct {
	File   string `json:"file"`
	Line   int    `json:"line,omitempty"`
	Offset int64  `json:"offset,omitempty"`
}

// Interval 是受影响的链序号区间（闭区间）。
type Interval struct {
	FromSeq uint64 `json:"from_seq"`
	ToSeq   uint64 `json:"to_seq"`
}

// Issue 是一条取证结论。
type Issue struct {
	Type     string    `json:"type"`
	Seq      uint64    `json:"seq"`
	Position Position  `json:"position"`
	Affected *Interval `json:"affected,omitempty"`
	Expected string    `json:"expected,omitempty"`
	Actual   string    `json:"actual,omitempty"`
	Detail   string    `json:"detail,omitempty"`
}

// SegmentCheck 是单个 WORM 段的校验摘要。
type SegmentCheck struct {
	ID         string `json:"id"`
	FirstSeq   uint64 `json:"first_seq"`
	LastSeq    uint64 `json:"last_seq"`
	Count      int64  `json:"count"`
	OK         bool   `json:"ok"`
	MerkleRoot string `json:"merkle_root"`
	FileSHA256 string `json:"file_sha256"`
}

// Checked 统计扫描范围。
type Checked struct {
	Records         int64  `json:"records"`
	RecordsInWindow int64  `json:"records_in_window"`
	Segments        int    `json:"segments"`
	FromSeq         uint64 `json:"from_seq"`
	ToSeq           uint64 `json:"to_seq"`
}

// HeadInfo 是 SQLite 中持久化的链头。
type HeadInfo struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

// Report 是 verify 的完整输出。
type Report struct {
	OK               bool           `json:"ok"`
	DataDir          string         `json:"data_dir"`
	Window           *TimeWindow    `json:"window,omitempty"`
	Checked          Checked        `json:"checked"`
	Head             HeadInfo       `json:"head"`
	Segments         []SegmentCheck `json:"segments,omitempty"`
	Issues           []Issue        `json:"issues,omitempty"`
	FirstTampered    *Issue         `json:"first_tampered,omitempty"`
	AffectedInterval *Interval      `json:"affected_interval,omitempty"`
	ElapsedMS        int64          `json:"elapsed_ms"`
}

type verifier struct {
	dir     string
	opts    VerifyOptions
	st      *store
	window  bool
	maxSeen uint64
	minSeen uint64
	haveAny bool
	expPrev string

	scanned int64
	winRec  int64
	winFrom uint64
	winTo   uint64

	issues    []Issue
	segChecks []SegmentCheck
}

// Verify 校验数据目录中任意时间窗口内的审计链完整性。
//
// 它会读取 SQLite 元数据、重算每条记录的哈希、重算每个 WORM 段的 Merkle
// root 与文件 SHA-256，并检测删除、重排、内容修改和整段缺失。发现断链时
// 返回的 Report 包含第一条被篡改记录的位置与受影响区间。
func Verify(dir string, opts VerifyOptions) (*Report, error) {
	start := time.Now()
	if !opts.From.IsZero() && !opts.To.IsZero() && opts.From.After(opts.To) {
		return nil, fmt.Errorf("from %s is after to %s", opts.From, opts.To)
	}
	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}
	lock, err := openFileLock(filepath.Join(dir, lockFile))
	if err != nil {
		return nil, fmt.Errorf("open lock: %w", err)
	}
	defer lock.Close()
	if err := lock.RLock(); err != nil {
		return nil, fmt.Errorf("acquire verify lock: %w", err)
	}
	defer lock.Unlock()

	st, err := openStore(dir)
	if err != nil {
		return nil, err
	}
	defer st.Close()

	v := &verifier{
		dir:    dir,
		opts:   opts,
		st:     st,
		window: !opts.From.IsZero() || !opts.To.IsZero(),
	}
	if err := v.run(); err != nil {
		return nil, err
	}
	rep := v.report()
	rep.ElapsedMS = time.Since(start).Milliseconds()
	return rep, nil
}

func (v *verifier) run() error {
	v.winFrom = 0
	v.winTo = 0

	segments, err := v.st.listSegments()
	if err != nil {
		return err
	}
	known := make(map[string]bool, len(segments))
	for _, m := range segments {
		known[m.ID] = true
	}

	// 检查 worm 目录里是否存在数据库未登记的段文件（整段插入）。
	if files, err := filepath.Glob(filepath.Join(v.dir, wormDir, "*.jsonl")); err == nil {
		for _, path := range files {
			id := filepath.Base(path)
			if known[id] {
				continue
			}
			pos := Position{File: filepath.ToSlash(filepath.Join(wormDir, id))}
			seq := uint64(0)
			if dr, err := readFirstRecord(path); err == nil {
				seq = dr.Seq
			}
			v.addIssue(IssueUnregisteredSegment, seq, pos, nil, "",
				id, "sealed segment file is not registered in SQLite")
		}
	}

	v.initSegmentChecks(segments)

	for i := range segments {
		m := &segments[i]
		path := filepath.Join(v.dir, filepath.FromSlash(m.Path))
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				aff := &Interval{FromSeq: m.FirstSeq, ToSeq: m.LastSeq}
				v.addIssue(IssueSegmentMissing, m.FirstSeq, Position{File: m.Path}, aff, "",
					m.LastHash, "sealed segment file is missing")
				if m.LastSeq > v.maxSeen {
					v.maxSeen = m.LastSeq
				}
				v.expPrev = m.LastHash
				v.markSegment(m.ID, false)
				continue
			}
			return err
		}
		v.scanSegment(m, path)
	}

	act, err := v.st.loadActive()
	if err != nil {
		return err
	}
	activePath := filepath.Join(v.dir, activeFile)
	if act != nil {
		if _, err := os.Stat(activePath); err != nil {
			if os.IsNotExist(err) {
				aff := &Interval{FromSeq: act.FirstSeq, ToSeq: act.LastSeq}
				v.addIssue(IssueSegmentMissing, act.FirstSeq, Position{File: activeFile}, aff, "",
					act.LastHash, "active audit file is missing (records not sealed)")
				if act.LastSeq > v.maxSeen {
					v.maxSeen = act.LastSeq
				}
				v.expPrev = act.LastHash
			} else {
				return err
			}
		} else if info, _ := os.Stat(activePath); info != nil && info.Size() > 0 {
			v.scanActive(activePath, act)
		}
	} else if info, err := os.Stat(activePath); err == nil && info.Size() > 0 {
		// 文件存在但 SQLite 无活跃段登记（可能是崩溃后未完成元数据更新）。
		v.scanActive(activePath, nil)
	}

	head, err := v.st.loadHead()
	if err != nil {
		return err
	}
	if head.Seq > v.maxSeen {
		aff := &Interval{FromSeq: v.maxSeen + 1, ToSeq: head.Seq}
		v.addIssue(IssueRecordDeletion, v.maxSeen+1, Position{File: activeFile}, aff, head.Hash, "",
			fmt.Sprintf("SQLite chain head %d is ahead of disk (%d)", head.Seq, v.maxSeen))
	} else if head.Seq < v.maxSeen {
		v.addIssue(IssueMetadataMismatch, v.maxSeen, Position{File: activeFile}, nil, "",
			fmt.Sprintf("head=%d", head.Seq),
			fmt.Sprintf("SQLite chain head is behind disk (disk=%d)", v.maxSeen))
	} else if v.maxSeen > 0 && head.Hash != v.expPrev {
		v.addIssue(IssueMetadataMismatch, v.maxSeen, Position{File: activeFile}, nil, v.expPrev, head.Hash,
			"SQLite chain head hash does not match last record")
	}
	return nil
}

func (v *verifier) initSegmentChecks(segments []segmentMeta) {
	v.segChecks = make([]SegmentCheck, 0, len(segments))
	for _, m := range segments {
		v.segChecks = append(v.segChecks, SegmentCheck{
			ID: m.ID, FirstSeq: m.FirstSeq, LastSeq: m.LastSeq, Count: m.Count, OK: true,
			MerkleRoot: m.MerkleRoot, FileSHA256: m.FileSHA256,
		})
	}
}

func (v *verifier) scanSegment(m *segmentMeta, path string) {
	before := len(v.issues)
	var leaves [][32]byte
	var firstPos Position
	var actualFirst, actualLast uint64
	var actualCount int64

	fileSHA, size, _, err := scanFile(path, func(raw []byte, dr *diskRecord, line int, offset int64) error {
		pos := Position{File: m.Path, Line: line, Offset: offset}
		if actualFirst == 0 {
			actualFirst = dr.Seq
			firstPos = pos
		}
		actualLast = dr.Seq
		actualCount++
		if leaf, derr := decodeHash(dr.Hash); derr == nil {
			leaves = append(leaves, leaf)
		}
		v.observe(dr, pos)
		return nil
	})

	if err != nil {
		var ce *corruptRecordError
		pos := firstPos
		detail := err.Error()
		if errors.As(err, &ce) {
			pos = Position{File: m.Path, Line: ce.Line, Offset: ce.Offset}
			detail = fmt.Sprintf("cannot parse record: %v", ce.Err)
		}
		v.addIssue(IssueCorruptRecord, v.maxSeen+1, pos, nil, "", "", detail)
		if m.LastSeq > v.maxSeen {
			v.maxSeen = m.LastSeq
		}
		v.expPrev = m.LastHash
		v.markSegment(m.ID, false)
		return
	}

	if actualLast < m.LastSeq {
		aff := &Interval{FromSeq: actualLast + 1, ToSeq: m.LastSeq}
		v.addIssue(IssueRecordDeletion, actualLast+1, Position{File: m.Path, Offset: size}, aff, "",
			"", fmt.Sprintf("segment metadata expects last seq %d but file ends at %d", m.LastSeq, actualLast))
		v.maxSeen = m.LastSeq
		v.expPrev = m.LastHash
	} else if actualLast > m.LastSeq {
		v.addIssue(IssueMetadataMismatch, actualLast, Position{File: m.Path}, nil, "",
			fmt.Sprintf("actual last seq %d", actualLast),
			fmt.Sprintf("file contains seq beyond segment metadata (%d)", m.LastSeq))
	}

	segIssues := len(v.issues) - before
	if segIssues == 0 {
		if actualFirst != m.FirstSeq || actualLast != m.LastSeq || actualCount != m.Count ||
			fileSHA != m.FileSHA256 || size != m.Size {
			v.addIssue(IssueMetadataMismatch, actualFirst, firstPos, nil, m.FileSHA256, fileSHA,
				fmt.Sprintf("segment metadata mismatch (count db=%d file=%d size db=%d file=%d)",
					m.Count, actualCount, m.Size, size))
		} else if root := merkleRoot(leaves); root != m.MerkleRoot {
			v.addIssue(IssueMetadataMismatch, actualFirst, firstPos, nil, m.MerkleRoot, root,
				"segment Merkle root does not match recomputed root")
		}
	}
	v.markSegment(m.ID, len(v.issues) == before)
}

func (v *verifier) markSegment(id string, ok bool) {
	for i := range v.segChecks {
		if v.segChecks[i].ID == id {
			v.segChecks[i].OK = ok
			return
		}
	}
}

func (v *verifier) scanActive(path string, act *activeMeta) {
	var lastSeq uint64
	var lastPos Position
	var count int64
	_, size, _, err := scanFile(path, func(raw []byte, dr *diskRecord, line int, offset int64) error {
		pos := Position{File: activeFile, Line: line, Offset: offset}
		lastSeq = dr.Seq
		lastPos = pos
		count++
		v.observe(dr, pos)
		return nil
	})
	if err != nil {
		var ce *corruptRecordError
		pos := lastPos
		detail := err.Error()
		if errors.As(err, &ce) {
			pos = Position{File: activeFile, Line: ce.Line, Offset: ce.Offset}
			detail = fmt.Sprintf("cannot parse record: %v", ce.Err)
		}
		v.addIssue(IssueCorruptRecord, v.maxSeen+1, pos, nil, "", "", detail)
	}
	if act != nil {
		if lastSeq < act.LastSeq {
			aff := &Interval{FromSeq: lastSeq + 1, ToSeq: act.LastSeq}
			v.addIssue(IssueRecordDeletion, lastSeq+1, Position{File: activeFile, Offset: size}, aff, "",
				act.LastHash, fmt.Sprintf("active metadata expects last seq %d but file ends at %d", act.LastSeq, lastSeq))
			v.maxSeen = act.LastSeq
			v.expPrev = act.LastHash
		} else if lastSeq > act.LastSeq {
			v.addIssue(IssueMetadataMismatch, lastSeq, lastPos, nil, "",
				fmt.Sprintf("seq %d", lastSeq),
				fmt.Sprintf("active file has records beyond SQLite metadata (%d)", act.LastSeq))
		} else if count != act.Count {
			v.addIssue(IssueMetadataMismatch, lastSeq, lastPos, nil, fmt.Sprint(act.Count), fmt.Sprint(count),
				"active record count does not match SQLite metadata")
		}
	} else if count > 0 {
		v.addIssue(IssueMetadataMismatch, lastSeq, lastPos, nil, "", "",
			"active file contains records but SQLite has no active segment row (possible crash)")
	}
}

// observe 对单条记录做链校验。它是 verify 的核心。
func (v *verifier) observe(dr *diskRecord, pos Position) {
	v.scanned++

	// 1) 记录自身哈希：绑定 prev/seq/time/event 全部内容。
	computed := chainHash(dr.Prev, dr.Seq, dr.Time, dr.Event)
	if computed != dr.Hash {
		v.addIssue(IssueContentModified, dr.Seq, pos, nil, computed, dr.Hash,
			"record hash does not match its content (event/prev/seq/time tampered)")
	}

	// 2) 时间窗口统计（时间戳已被哈希绑定，无法单独篡改）。
	inWin := true
	if v.window {
		if !v.opts.From.IsZero() && dr.Time.Before(v.opts.From) {
			inWin = false
		}
		if !v.opts.To.IsZero() && dr.Time.After(v.opts.To) {
			inWin = false
		}
	}
	if inWin {
		v.winRec++
		if v.winFrom == 0 {
			v.winFrom = dr.Seq
		}
		v.winTo = dr.Seq
	}

	if !v.haveAny {
		v.haveAny = true
		v.minSeen = dr.Seq
		if dr.Seq > 1 {
			aff := &Interval{FromSeq: 1, ToSeq: dr.Seq - 1}
			v.addIssue(IssueRecordDeletion, 1, pos, aff, "", "",
				fmt.Sprintf("chain starts at seq %d, seq 1..%d is missing", dr.Seq, dr.Seq-1))
			v.expPrev = dr.Prev
		} else if dr.Prev != genesisPrev {
			v.addIssue(IssueChainBreak, dr.Seq, pos, nil, genesisPrev, dr.Prev,
				"first record must have empty prev")
		}
		v.maxSeen = dr.Seq
		v.expPrev = dr.Hash
		return
	}
	if dr.Seq < v.minSeen {
		v.minSeen = dr.Seq
	}

	switch {
	case dr.Seq > v.maxSeen+1:
		aff := &Interval{FromSeq: v.maxSeen + 1, ToSeq: dr.Seq - 1}
		v.addIssue(IssueRecordDeletion, v.maxSeen+1, pos, aff, "",
			fmt.Sprintf("found seq %d", dr.Seq),
			fmt.Sprintf("expected seq %d; records %d..%d are missing", v.maxSeen+1, v.maxSeen+1, dr.Seq-1))
		v.maxSeen = dr.Seq
		v.expPrev = dr.Hash
	case dr.Seq == v.maxSeen+1:
		if dr.Prev != v.expPrev {
			v.addIssue(IssueChainBreak, dr.Seq, pos, nil, v.expPrev, dr.Prev,
				"prev hash does not link to the previous record")
		}
		v.maxSeen = dr.Seq
		v.expPrev = dr.Hash
	default: // seq <= maxSeen：重复或乱序
		typ := IssueRecordReorder
		detail := fmt.Sprintf("out-of-order seq %d (max seen %d)", dr.Seq, v.maxSeen)
		if dr.Seq == v.maxSeen {
			typ = IssueDuplicateSeq
			detail = fmt.Sprintf("duplicate seq %d", dr.Seq)
		}
		v.addIssue(typ, dr.Seq, pos, nil, "", "", detail)
	}
}

func (v *verifier) addIssue(typ string, seq uint64, pos Position, aff *Interval, expected, actual, detail string) {
	v.issues = append(v.issues, Issue{
		Type: typ, Seq: seq, Position: pos, Affected: aff,
		Expected: expected, Actual: actual, Detail: detail,
	})
}

func (v *verifier) report() *Report {
	issues := v.issues
	if v.window {
		issues = nil
		for _, is := range v.issues {
			if v.issueInWindow(is) {
				issues = append(issues, is)
			}
		}
	}
	sort.SliceStable(issues, func(i, j int) bool {
		si, sj := issues[i].Seq, issues[j].Seq
		if si == 0 {
			si = ^uint64(0)
		}
		if sj == 0 {
			sj = ^uint64(0)
		}
		return si < sj
	})

	rep := &Report{
		OK:      len(issues) == 0,
		DataDir: v.dir,
		Checked: Checked{
			Records:         v.scanned,
			RecordsInWindow: v.winRec,
			Segments:        len(v.segChecks),
			FromSeq:         v.winFrom,
			ToSeq:           v.winTo,
		},
		Issues:   issues,
		Segments: v.segChecks,
	}
	if v.window {
		win := &TimeWindow{}
		if !v.opts.From.IsZero() {
			t := v.opts.From
			win.From = &t
		}
		if !v.opts.To.IsZero() {
			t := v.opts.To
			win.To = &t
		}
		rep.Window = win
	}
	if head, err := v.st.loadHead(); err == nil {
		rep.Head = HeadInfo{Seq: head.Seq, Hash: head.Hash}
	}
	if len(issues) > 0 {
		first := issues[0]
		rep.FirstTampered = &first
		rep.AffectedInterval = affectedInterval(issues)
	}
	return rep
}

func (v *verifier) issueInWindow(is Issue) bool {
	if !v.window {
		return true
	}
	if is.Seq == 0 {
		return true // 元数据类问题无法定位到窗口内记录
	}
	if v.winFrom == 0 && v.winTo == 0 {
		return false
	}
	from, to := is.Seq, is.Seq
	if is.Affected != nil {
		from, to = is.Affected.FromSeq, is.Affected.ToSeq
	}
	if to < from {
		from, to = to, from
	}
	return !(to < v.winFrom || from > v.winTo)
}

// affectedInterval 计算从第一条异常开始的连续受影响区间。
func affectedInterval(issues []Issue) *Interval {
	var from, to uint64
	started := false
	for _, is := range issues {
		if is.Seq == 0 {
			continue
		}
		a, b := is.Seq, is.Seq
		if is.Affected != nil {
			a, b = is.Affected.FromSeq, is.Affected.ToSeq
		}
		if a > b {
			a, b = b, a
		}
		if !started {
			from, to = a, b
			started = true
			continue
		}
		if a <= to+1 {
			if b > to {
				to = b
			}
		} else {
			break
		}
	}
	if !started {
		return nil
	}
	return &Interval{FromSeq: from, ToSeq: to}
}
