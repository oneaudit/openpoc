package types

type AggregatorResult struct {
	ExploitDB []ExploitDB      `json:"exploitdb"`
	InTheWild []InTheWild      `json:"itw"`
	Openpoc   []OpenpocProduct `json:"openpoc"`
}
