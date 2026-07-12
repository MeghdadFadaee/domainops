//go:build !darwin && !linux

package lockfile

import (
	"errors"
	"os"
	"path/filepath"
)

type Lock struct {
	path string
	file *os.File
}

func Acquire(path string) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil, errors.New("DomainOps is already running for this data directory")
	}
	if err != nil {
		return nil, err
	}
	return &Lock{path: path, file: file}, nil
}

func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := l.file.Close()
	_ = os.Remove(l.path)
	l.file = nil
	return err
}
