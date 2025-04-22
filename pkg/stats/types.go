package stats

type Stats struct {
	TotalFiles       int
	TotalValue       float64
	TotalCount       int
	CategoryCounters map[string]int
}

type FileJob struct {
	Path string
}
