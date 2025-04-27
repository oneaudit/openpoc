package types

import (
	"io/fs"
	"time"
)

type Target struct {
	URL       string
	Folder    string
	Branch    string
	Skip      bool
	Completed bool
	Range     time.Duration
}

type FileJob struct {
	Path     string
	Folder   string
	FileInfo fs.FileInfo
}

type ProcessFunction[T any] func(job FileJob) ([]*T, error)
