package types

type AggregatorResult struct {
	ExploitDB []ExploitDB      `json:"exploitdb"`
	Openpoc   []OpenpocProduct `json:"openpoc"`
}
