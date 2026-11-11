# audit-service

内部服务的**防篡改审计日志**组件（Go）。在原“顺序追加 JSONL”的基础上增加了
哈希链、按小时封存 WORM、SQLite 链头/Merkle 元数据、跨进程并发写入与取证式
完整性校验。

## 设计

### 记录格式

每条写盘记录是一行 JSON：

```json
{"seq":1,"prev":"<hex>","hash":"<hex>","time":"2026-11-11T10:00:00.123456789Z","event":{...原始事件...}}
```

哈希把前后记录和事件内容绑定在一起：

```
hash = SHA256( "annot-audit:chain:v1\x00" || prev || 0x00 ||
               be64(seq) || 0x00 || time(UTC, RFC3339Nano) || 0x00 || event_bytes )
```

- 事件内容用 `encoding/json` 的确定性输出（map 键有序），并原样保存为
  `json.RawMessage`；校验时用同一段字节重算，避免“重新序列化导致哈希漂移”。
- `prev` 指向上一条记录的 `hash`，第一条的 `prev` 为空串（创世）。
- 改动任意一条记录的 seq/prev/time/event 都会让它及其之后所有记录校验失败。

### 封存（WORM）

- 活跃文件 `events.jsonl`，每跨过整点小时自动封存（也可显式 `Seal()`）。
- 封存产物：`worm/seg-YYYYMMDDTHHMMSSZ-<first>-<last>.jsonl`
  \+ 同名 `.manifest.json`（含 first/last seq、count、文件 SHA-256、大小、Merkle root）。
- 顺序：复制活跃文件到 WORM 目录（`O_CREATE|O_EXCL`，不覆盖）→ `fsync` →
  写 manifest → 写 SQLite → 截断活跃文件。WORM 段创建后不再修改。
- `Options.WORMImmutable` 开启后把段文件与 manifest 置为 `0444`，生产环境建议开启；
  若底层存储支持 Object Lock / `chattr +i` 可在此基础上进一步加固。

### 元数据（SQLite）

`data/audit.db`（WAL、`synchronous=NORMAL`、`busy_timeout=10s`）：

- `chain_head(id=1, seq, hash)`：全局链头，崩溃后用于对齐磁盘；
- `segments(...)`：每个已封存段的边界、哈希、Merkle root、文件 SHA-256、大小；
- `active_segment(id=1, ...)`：当前活跃段的起始 seq/prev/time 与计数。

### 并发写入（多进程同链）

- 每个进程先写进程内缓冲，按 `BatchSize`（默认 128）/ `FlushInterval`（默认 10ms）
  组成批次。
- 组提交时持**跨进程文件锁**（Windows `LockFileEx`，Unix `flock`），在锁内读取
  链头 → 逐条分配 seq、计算 hash、顺序追加 → 刷盘 → 更新 SQLite → 释放锁。
  因此多个进程共享同一条严格有序的链。
- 活跃文件句柄在批次之间保持打开（`bufio` 1MB），避免 Windows 上频繁 open/close
  带来的吞吐损失；封存时用“复制 + 截断”而非 rename，规避打开文件的限制。
- 启动时自动：迁移旧版无链 JSONL → 去重已封存前缀（崩溃窗口）→ 修复半截尾行 →
  用磁盘实际链头与 SQLite 对齐。

### 校验（verify）

`audit.Verify(dir, VerifyOptions{From, To})` 流式扫描所有段与活跃文件，重算每条
记录的哈希与链接关系，并校验段文件 SHA-256 / 大小 / Merkle root / 记录数。

可检测：

| 类型 | 说明 |
| --- | --- |
| `content_modified` | 记录内容被改 |
| `record_deleted` | 中间记录被删（seq 断洞或段尾缺失） |
| `record_reordered` | seq/prev 顺序被调换 |
| `duplicate_seq` | 重复 seq |
| `hash_chain_broken` | `prev` 与上一条 `hash` 对不上 |
| `corrupt_record` | 行无法解析 |
| `segment_missing` | 整段文件缺失 |
| `metadata_mismatch` | 段元数据 / Merkle / 文件哈希不符 |
| `unregistered_segment` | 磁盘上存在未登记的段文件 |

报告给出 `first_tampered` 的**文件:行:偏移**、期望/实际值，以及受影响的
seq 区间 `affected_interval`；支持只对时间窗口内的记录做统计。

## 目录

```
cmd/server         HTTP 服务（POST/GET /events，GET /healthz），生产配置开启 WORM
cmd/verify         完整性校验（支持 -from/-to 时间窗口、-json 报告）
cmd/gen            批量生成事件，用于吞吐和 verify 性能压测
cmd/stress         多进程并发写入压测，结束时校验全局链序
bench              HTTP 端并发压测客户端（改造前既有）
internal/audit     记录格式、哈希链、SQLite、锁、组提交 Writer、verify
data/              运行时数据目录（已 gitignore）
```

数据目录布局：

```
data/
├── audit.db                # SQLite（+ -wal/-shm）
├── .audit.lock             # 跨进程锁文件
├── events.jsonl            # 当前活跃段
└── worm/
    ├── seg-...-<f>-<l>.jsonl
    └── seg-...-<f>-<l>.manifest.json
```

## 运行

```bash
go build ./...
go test ./...                 # 含篡改场景、旧数据迁移、多进程并发等测试

# 起服务（生产配置：封存置只读 + 退出时封存）
go run ./cmd/server -addr 127.0.0.1:8099 -data data

# 写一条
curl -s -X POST http://127.0.0.1:8099/events \
  -H 'content-type: application/json' \
  -d '{"id":"evt-1","actor":"alice","action":"read","resource":"doc/1"}'

# 查最近 20 条
curl -s 'http://127.0.0.1:8099/events?limit=20'

# 全量校验 / 任意时间窗口校验 / JSON 报告
go run ./cmd/verify -data data
go run ./cmd/verify -data data -from 2026-11-11T10:00:00Z -to 2026-11-11T11:00:00Z
go run ./cmd/verify -data data -json
```

`cmd/verify` 退出码：`0` 完好，`1` 检测到篡改，`2` 参数/执行错误。

## 压测数据

机器：12th Gen Intel i5-12500H（Windows 11，`goos=windows/amd64`）。

写入吞吐（`go test ./internal/audit -bench=BenchmarkWrite -benchtime=3s -run=^$`）：

```
基线 JSONL 追加（改造前）    ~7916 ns/op
改造后（哈希链 + 组提交）    ~3023 ns/op   （本机实测，约 2.6x 提升）
```

组提交把每条事件的持锁与落盘摊薄到批次上，因此引入哈希链与 WORM 后吞吐不降反升，
满足“下降不超过 10%”的要求。

百万级 verify（`go run ./cmd/gen -n 1000000 -data data/perf/run1 -batch 512 -hours 24 -seal -verify`）：

```
generated: n=1000000 elapsed=5.379s throughput=185922/s
verify:    ok=true records=1000000 segments=24 elapsed=2853ms
```

**100 万条校验耗时 ~2.85s，远低于 30s 要求。**

多进程并发（`go run ./cmd/stress ...`，结束时校验全局链序）：

```
# 8 进程 × 5000 条，每进程退出时封存
stress: procs=8 per_process=5000 total=40000 batch=128 seal=true
write:  wall=1.105s throughput=36210/s slowest_child=440ms
verify: ok=true records=40000 segments=5 elapsed=166ms

# 8 进程 × 20000 条，批量 512，不封存（纯吞吐）
stress: procs=8 per_process=20000 total=160000 batch=512 seal=false
write:  wall=364ms throughput=439157/s slowest_child=278ms
verify: ok=true records=160000 segments=0 elapsed=339ms
```

多进程结果 `ok=true`，说明跨进程写入后链仍然严格有序、无重复 seq。

## 威胁模型与限制

- 假设 SQLite 元数据与 WORM 段存储是可信的；verify 依赖二者做交叉校验。
- 能检测**局部**删除、重排、改内容与整段删除。若攻击者拥有对整个目录（含
  SQLite 与全部段）的完整写权限并能从头重算整条链，纯本地哈希链无法发现——
  这需要外部锚定（定期把链头/Merkle root 推送到独立的只写存储、透明日志或
  签名时间戳）。按题目约束，本实现不依赖任何外部区块链服务。
- `0444`/只读是软性加固，不等同于存储层 WORM；生产应使用支持 Object Lock 的
  对象存储或 `chattr +i` 等由底层保证的不可变语义。

## 约定

- 不提交 `data/`、`*.jsonl`、`.env` 以及任何密钥；
- 对外接口（`/events` 的路径与响应结构）保持兼容。
