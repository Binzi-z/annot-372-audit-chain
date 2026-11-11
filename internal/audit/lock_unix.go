//go:build !windows

package audit

import (
	"os"
	"syscall"
)

// fileLock 是跨进程的 OS 级文件锁（POSIX flock）。
type fileLock struct {
	f *os.File
}

func openFileLock(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	return &fileLock{f: f}, nil
}

func (l *fileLock) Lock() error   { return syscall.Flock(int(l.f.Fd()), syscall.LOCK_EX) }
func (l *fileLock) RLock() error  { return syscall.Flock(int(l.f.Fd()), syscall.LOCK_SH) }
func (l *fileLock) Unlock() error { return syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN) }

func (l *fileLock) Close() error { return l.f.Close() }
