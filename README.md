# audit-service

内部服务的审计日志组件（Go）。当前状态：**能跑、能写、能查，但没有任何完整性保护**。

## 结构

```
cmd/server         HTTP 服务（POST /events 写入，GET /events 查询，GET /healthz）
internal/audit     审计写入与读取（顺序追加 JSONL）
bench              并发写入压测客户端
data/              运行时数据目录（已 gitignore）
```

## 运行

```bash
go build ./...
go test ./...

# 起服务
go run ./cmd/server -addr 127.0.0.1:8099 -data data

# 写一条
curl -s -X POST http://127.0.0.1:8099/events \
  -H 'content-type: application/json' \
  -d '{"id":"evt-1","actor":"alice","action":"read","resource":"doc/1"}'

# 查最近 20 条
curl -s 'http://127.0.0.1:8099/events?limit=20'
```

## 基线压测

```bash
# 写入吞吐基线（改造前后对比用）
go test ./internal/audit -bench=BenchmarkWrite -benchtime=3s -run=^$ | tee before.txt

# 端到端并发压测
go run ./bench -n 2000 -c 32
```

## 已知限制（当前实现）

- 事件之间没有任何关联，删掉中间一行看不出来；
- 没有哈希/签名，文件被改过无法验证；
- 只有进程内互斥，多进程同时写不保证顺序；
- 按文件大小轮转，轮转后不可追溯。

## 约定

- 不提交 `data/`、`*.jsonl`、`.env` 以及任何密钥；
- 对外接口（`/events` 的路径与响应结构）保持兼容。
