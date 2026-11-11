package audit

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const (
	dbFile     = "audit.db"
	activeFile = "events.jsonl"
	wormDir    = "worm"
	lockFile   = ".audit.lock"
)

// chainHead 是全局链的最新位置（SQLite 持久化，跨进程共享）。
type chainHead struct {
	Seq  uint64
	Hash string
}

// segmentMeta 是一条已封存 WORM 段的元数据。
type segmentMeta struct {
	ID         string
	Path       string // 相对于数据目录
	Hour       string
	FirstSeq   uint64
	LastSeq    uint64
	FirstPrev  string
	LastHash   string
	FirstTime  string
	LastTime   string
	Count      int64
	MerkleRoot string
	FileSHA256 string
	Size       int64
	SealedAt   string
}

// activeMeta 描述当前未封存的活跃文件状态。
type activeMeta struct {
	File      string
	Hour      string
	FirstSeq  uint64
	FirstPrev string
	FirstTime string
	LastSeq   uint64
	LastHash  string
	Count     int64
	StartedAt string
}

type store struct {
	db *sql.DB
}

func openStore(dir string) (*store, error) {
	dsn := "file:" + filepath.ToSlash(filepath.Join(dir, dbFile)) +
		"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &store{db: db}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *store) init() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS chain_head (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	seq INTEGER NOT NULL,
	hash TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
INSERT OR IGNORE INTO chain_head(id, seq, hash, updated_at) VALUES (1, 0, '', '');
CREATE TABLE IF NOT EXISTS segments (
	id TEXT PRIMARY KEY,
	path TEXT NOT NULL,
	hour TEXT NOT NULL,
	first_seq INTEGER NOT NULL,
	last_seq INTEGER NOT NULL,
	first_prev TEXT NOT NULL,
	last_hash TEXT NOT NULL,
	first_time TEXT NOT NULL,
	last_time TEXT NOT NULL,
	count INTEGER NOT NULL,
	merkle_root TEXT NOT NULL,
	file_sha256 TEXT NOT NULL,
	size INTEGER NOT NULL,
	sealed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_segments_first_seq ON segments(first_seq);
CREATE TABLE IF NOT EXISTS active_segment (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	file TEXT NOT NULL,
	hour TEXT NOT NULL,
	first_seq INTEGER NOT NULL,
	first_prev TEXT NOT NULL,
	first_time TEXT NOT NULL,
	last_seq INTEGER NOT NULL,
	last_hash TEXT NOT NULL,
	count INTEGER NOT NULL,
	started_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
`)
	return err
}

func (s *store) Close() error { return s.db.Close() }

func (s *store) loadHead() (chainHead, error) {
	var h chainHead
	err := s.db.QueryRow(`SELECT seq, hash FROM chain_head WHERE id = 1`).Scan(&h.Seq, &h.Hash)
	if err != nil {
		return chainHead{}, fmt.Errorf("load chain head: %w", err)
	}
	return h, nil
}

func (s *store) saveHead(h chainHead) error {
	_, err := s.db.Exec(`UPDATE chain_head SET seq = ?, hash = ?, updated_at = ? WHERE id = 1`,
		toDBUint(h.Seq), h.Hash, fmtTime(time.Now()))
	return err
}

func (s *store) saveState(h chainHead, act *activeMeta) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE chain_head SET seq = ?, hash = ?, updated_at = ? WHERE id = 1`,
		toDBUint(h.Seq), h.Hash, fmtTime(time.Now())); err != nil {
		return err
	}
	if act == nil {
		if _, err := tx.Exec(`DELETE FROM active_segment WHERE id = 1`); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(`
INSERT INTO active_segment(id, file, hour, first_seq, first_prev, first_time, last_seq, last_hash, count, started_at, updated_at)
VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
 file=excluded.file, hour=excluded.hour, first_seq=excluded.first_seq, first_prev=excluded.first_prev,
 first_time=excluded.first_time, last_seq=excluded.last_seq, last_hash=excluded.last_hash,
 count=excluded.count, started_at=excluded.started_at, updated_at=excluded.updated_at`,
			act.File, act.Hour, toDBUint(act.FirstSeq), act.FirstPrev, act.FirstTime,
			toDBUint(act.LastSeq), act.LastHash, act.Count, act.StartedAt, fmtTime(time.Now())); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *store) insertSegment(m segmentMeta) error {
	_, err := s.db.Exec(`
INSERT OR REPLACE INTO segments(id, path, hour, first_seq, last_seq, first_prev, last_hash,
 first_time, last_time, count, merkle_root, file_sha256, size, sealed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, m.Path, m.Hour, toDBUint(m.FirstSeq), toDBUint(m.LastSeq), m.FirstPrev, m.LastHash,
		m.FirstTime, m.LastTime, m.Count, m.MerkleRoot, m.FileSHA256, m.Size, m.SealedAt)
	return err
}

func (s *store) listSegments() ([]segmentMeta, error) {
	rows, err := s.db.Query(`SELECT id, path, hour, first_seq, last_seq, first_prev, last_hash,
		first_time, last_time, count, merkle_root, file_sha256, size, sealed_at
		FROM segments ORDER BY first_seq, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []segmentMeta
	for rows.Next() {
		var m segmentMeta
		var firstSeq, lastSeq, size int64
		if err := rows.Scan(&m.ID, &m.Path, &m.Hour, &firstSeq, &lastSeq, &m.FirstPrev, &m.LastHash,
			&m.FirstTime, &m.LastTime, &m.Count, &m.MerkleRoot, &m.FileSHA256, &size, &m.SealedAt); err != nil {
			return nil, err
		}
		m.FirstSeq = uint64(firstSeq)
		m.LastSeq = uint64(lastSeq)
		m.Size = size
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *store) loadActive() (*activeMeta, error) {
	var a activeMeta
	var firstSeq, lastSeq int64
	err := s.db.QueryRow(`SELECT file, hour, first_seq, first_prev, first_time, last_seq, last_hash,
		count, started_at FROM active_segment WHERE id = 1`).
		Scan(&a.File, &a.Hour, &firstSeq, &a.FirstPrev, &a.FirstTime, &lastSeq, &a.LastHash,
			&a.Count, &a.StartedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.FirstSeq = uint64(firstSeq)
	a.LastSeq = uint64(lastSeq)
	return &a, nil
}

func (s *store) clearActive() error {
	_, err := s.db.Exec(`DELETE FROM active_segment WHERE id = 1`)
	return err
}

func toDBUint(v uint64) int64 {
	// SQLite INTEGER 为 64 位有符号；审计序号远小于 2^63。
	return int64(v)
}

func fmtTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}
