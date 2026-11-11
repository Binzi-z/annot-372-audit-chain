package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"annot-audit/internal/audit"
)

var (
	dataDir = flag.String("data", "data", "audit data directory")
	addr    = flag.String("addr", "127.0.0.1:8099", "listen address")
)

func main() {
	flag.Parse()

	// 生产环境把封存后的段设为只读（WORM）；若底层存储支持 Object Lock/
	// chattr +i，可在此基础上进一步加固。
	w, err := audit.NewWriterWithOptions(*dataDir, audit.Options{
		WORMImmutable: true,
		SealOnClose:   true,
	})
	if err != nil {
		log.Fatalf("init writer: %v", err)
	}
	defer w.Close()

	mux := http.NewServeMux()

	// POST /events  写入一条审计事件
	mux.HandleFunc("/events", func(rw http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var e audit.Event
			if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
				httpError(rw, http.StatusBadRequest, "invalid json: "+err.Error())
				return
			}
			if e.ID == "" {
				e.ID = fmt.Sprintf("evt-%d", time.Now().UnixNano())
			}
			if err := w.Write(e); err != nil {
				httpError(rw, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(rw, http.StatusCreated, map[string]any{"ok": true, "id": e.ID})

		case http.MethodGet:
			limit := 100
			if v := r.URL.Query().Get("limit"); v != "" {
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
					limit = n
				}
			}
			all, err := audit.ReadAll(*dataDir)
			if err != nil {
				httpError(rw, http.StatusInternalServerError, err.Error())
				return
			}
			if len(all) > limit {
				all = all[len(all)-limit:]
			}
			writeJSON(rw, http.StatusOK, map[string]any{"count": len(all), "events": all})

		default:
			httpError(rw, http.StatusMethodNotAllowed, "method not allowed")
		}
	})

	// GET /healthz 健康检查
	mux.HandleFunc("/healthz", func(rw http.ResponseWriter, r *http.Request) {
		writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "wrote": w.Count()})
	})

	log.Printf("audit service listening on %s, data dir %q", *addr, *dataDir)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Printf("server stopped: %v", err)
		os.Exit(1)
	}
}

func writeJSON(rw http.ResponseWriter, code int, v any) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(code)
	_ = json.NewEncoder(rw).Encode(v)
}

func httpError(rw http.ResponseWriter, code int, msg string) {
	writeJSON(rw, code, map[string]any{"ok": false, "error": msg})
}
