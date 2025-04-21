package types

type AggregatorResult struct {
	Openpoc []OpenpocProduct `json:"openpoc"`
}

type Target struct {
	URL       string
	Folder    string
	Branch    string
	Skip      bool
	Completed bool
}
