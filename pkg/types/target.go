package types

import "time"

type Target struct {
	URL       string
	Folder    string
	Branch    string
	Skip      bool
	Completed bool
	Range     time.Duration
}
