package types

type AggregatorResult struct {
	ExploitDB []ExploitDB      `json:"exploitdb"`
	InTheWild []InTheWild      `json:"itw"`
	Trickest  []Trickest       `json:"trickest"`
	Nomisec   []Nomisec        `json:"nomisec"`
	Openpoc   []OpenpocProduct `json:"openpoc"`
}
