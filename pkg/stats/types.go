package stats

import "openpoc/pkg/types"

type Stats struct {
	Year                string
	CVECount            int64
	ExploitCount        int64
	ExploitCountAverage float64
	CveScoreBoard       []CVEStat

	DomainMap        map[string]int
	DomainScoreBoard []DomainCount

	URLMap        map[string]int
	URLScoreBoard []URLCount

	ProviderMap map[string]*ProviderDetails
}

type ProviderDetails struct {
	// Count is the number of POC
	Count int64
	// Exclusive is the number of exclusive POC
	Exclusive int64
	// CVE is the number of CVEs having a POC
	CVE int64
	// ExclusiveCVE is the number of exclusive CVEs
	ExclusiveCVE int64
}

type DomainCount struct {
	Domain string
	Count  int
}

type URLCount struct {
	URL   string
	Count int
}

type CVEStat struct {
	CveID        string
	ExploitCount int64
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
