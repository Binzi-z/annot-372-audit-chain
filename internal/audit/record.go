package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"sync"
	"time"
)

// chainDomain 把本服务的哈希链与其它用途的 SHA-256 输入域隔离。
const chainDomain = "annot-audit:chain:v1\x00"

// genesisPrev 是第一条记录的 prev 值（空串）。
const genesisPrev = ""

// diskRecord 是审计文件中的一行。Event 保存原始事件字节，校验时必须对
// 原始字节做哈希，否则无法发现字段级的篡改。
type diskRecord struct {
	Seq   uint64          `json:"seq"`
	Prev  string          `json:"prev"`
	Hash  string          `json:"hash"`
	Time  time.Time       `json:"time"`
	Event json.RawMessage `json:"event"`
}

var hashPool = sync.Pool{New: func() any { return sha256.New() }}

// chainHash 计算一条记录的哈希：
//
//	SHA256(domain || prev || 0x00 || seq_be64 || 0x00 || ts || 0x00 || event_payload)
//
// prev 为前一条记录的哈希（十六进制），第一条为空串。ts 为记录时间（UTC,
// RFC3339Nano），payload 是事件的确定性 JSON 编码（encoding/json 对 map 键排序）。
func chainHash(prev string, seq uint64, ts time.Time, payload []byte) string {
	h := hashPool.Get().(hash.Hash)
	h.Reset()
	h.Write([]byte(chainDomain))
	h.Write([]byte(prev))
	h.Write([]byte{0})
	var seqb [8]byte
	binary.BigEndian.PutUint64(seqb[:], seq)
	h.Write(seqb[:])
	h.Write([]byte{0})
	h.Write([]byte(ts.UTC().Format(time.RFC3339Nano)))
	h.Write([]byte{0})
	h.Write(payload)
	sum := h.Sum(nil)
	hashPool.Put(h)
	return hex.EncodeToString(sum)
}

func appendUint64(b []byte, v uint64) []byte {
	if v == 0 {
		return append(b, '0')
	}
	var tmp [20]byte
	i := len(tmp)
	for v > 0 {
		i--
		tmp[i] = byte('0' + v%10)
		v /= 10
	}
	return append(b, tmp[i:]...)
}

// encodeRecord 手工拼接一行记录，避免对 payload 二次序列化，同时保证写入
// 磁盘的 event 字节与参与哈希的字节完全一致。
func encodeRecord(seq uint64, prev, hash string, ts time.Time, payload []byte) []byte {
	b := make([]byte, 0, len(payload)+len(prev)+len(hash)+96)
	b = append(b, `{"seq":`...)
	b = appendUint64(b, seq)
	b = append(b, `,"prev":"`...)
	b = append(b, prev...)
	b = append(b, `","hash":"`...)
	b = append(b, hash...)
	b = append(b, `","time":"`...)
	b = append(b, ts.UTC().Format(time.RFC3339Nano)...)
	b = append(b, `","event":`...)
	b = append(b, payload...)
	b = append(b, '}', '\n')
	return b
}

// decodeHash 将十六进制哈希解码为 32 字节，作为 Merkle 叶子。
func decodeHash(s string) ([32]byte, error) {
	var out [32]byte
	if len(s) != 64 {
		return out, fmt.Errorf("bad hash length %d", len(s))
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	copy(out[:], raw)
	return out, nil
}

func encodeHash(h [32]byte) string {
	return hex.EncodeToString(h[:])
}

func hashPair(a, b [32]byte) [32]byte {
	var buf [64]byte
	copy(buf[:32], a[:])
	copy(buf[32:], b[:])
	return sha256.Sum256(buf[:])
}

// merkleRoot 计算叶子哈希的 Merkle 根。奇数层复制最后一个节点（比特币风格）。
func merkleRoot(leaves [][32]byte) string {
	if len(leaves) == 0 {
		return encodeHash(sha256.Sum256(nil))
	}
	lvl := make([][32]byte, len(leaves))
	copy(lvl, leaves)
	for len(lvl) > 1 {
		if len(lvl)%2 == 1 {
			lvl = append(lvl, lvl[len(lvl)-1])
		}
		next := make([][32]byte, len(lvl)/2)
		for i := 0; i < len(lvl); i += 2 {
			next[i/2] = hashPair(lvl[i], lvl[i+1])
		}
		lvl = next
	}
	return encodeHash(lvl[0])
}
