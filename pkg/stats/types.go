package stats

import "openpoc/pkg/types"

type Stats struct {
	CVECount            int
	ExploitCount        int
	ExploitCountAverage float64
	ScoreBoard          []CVEStat
}

type CVEStat struct {
	CveID        string
	ExploitCount int
}

type FileJob struct {
	Path   string
	Folder string
	CVE    string
}

type StatResult struct {
	FileJob FileJob
	Result  *types.AggregatorResult
}
