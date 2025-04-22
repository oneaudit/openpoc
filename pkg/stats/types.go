package stats

import "openpoc/pkg/types"

type Stats struct {
	CVECount            int
	ExploitCount        int
	ExploitCountAverage float64
}

type FileJob struct {
	Path   string
	Folder string
}

type StatResult struct {
	FileJob FileJob
	Result  *types.AggregatorResult
}
