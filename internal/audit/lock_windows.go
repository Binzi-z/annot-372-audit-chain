//go:build windows

package audit

import (
	"os"

	"golang.org/x/sys/windows"
)

// fileLock 是跨进程的 OS 级文件锁。Windows 使用 LockFileEx 的字节区间锁：
// 独占锁对应写者，共享锁对应 verify 之类的读者。
type fileLock struct {
	f  *os.File
	h  windows.Handle
	ov windows.Overlapped
}

func openFileLock(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	return &fileLock{f: f, h: windows.Handle(f.Fd())}, nil
}

func (l *fileLock) lock(exclusive bool) error {
	flags := uint32(0)
	if exclusive {
		flags = windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	return windows.LockFileEx(l.h, flags, 0, 1, 0, &l.ov)
}

func (l *fileLock) Lock() error   { return l.lock(true) }
func (l *fileLock) RLock() error  { return l.lock(false) }
func (l *fileLock) Unlock() error { return windows.UnlockFileEx(l.h, 0, 1, 0, &l.ov) }

func (l *fileLock) Close() error { return l.f.Close() }
