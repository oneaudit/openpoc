package types

type AggregatorResult struct {
	ExploitDB []ExploitDB      `json:"exploitdb"`
	InTheWild []InTheWild      `json:"itw"`
	Trickest  []Trickest       `json:"trickest"`
	Openpoc   []OpenpocProduct `json:"openpoc"`
}
