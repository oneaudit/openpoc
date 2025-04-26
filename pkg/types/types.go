package types

import (
	"sort"
	"time"
)

type AggregatorResult struct {
	ExploitDB []ExploitDB      `json:"exploitdb"`
	InTheWild []InTheWild      `json:"itw"`
	Trickest  []Trickest       `json:"trickest"`
	Nomisec   []Nomisec        `json:"nomisec"`
	Nuclei    []Nuclei         `json:"nuclei"`
	Openpoc   []OpenpocProduct `json:"openpoc"`
}

func NewAggregatorResult() *AggregatorResult {
	return &AggregatorResult{
		InTheWild: []InTheWild{},
		ExploitDB: []ExploitDB{},
		Trickest:  []Trickest{},
		Nomisec:   []Nomisec{},
		Nuclei:    []Nuclei{},
		Openpoc:   []OpenpocProduct{},
	}
}

func (a *AggregatorResult) ComputeOpenPoc() {
	merger := make(map[string]*OpenpocProduct)
	for _, exploit := range a.Trickest { // dirty, first
		addToMerger(&exploit, &merger)
	}
	for _, exploit := range a.InTheWild { // not often updated, second
		addToMerger(&exploit, &merger)
	}
	for _, exploit := range a.ExploitDB { // good third
		addToMerger(&exploit, &merger)
	}
	for _, exploit := range a.Nomisec { // the best, fourth
		addToMerger(&exploit, &merger)
	}
	for _, exploit := range a.Nuclei { // fifth, no impact
		addToMerger(&exploit, &merger)
	}
	for _, url := range merger {
		a.Openpoc = append(a.Openpoc, *url)
	}
}

func (a *AggregatorResult) Sort() {
	sort.Slice(a.ExploitDB, func(i, j int) bool {
		return a.ExploitDB[i].GetURL() < a.ExploitDB[j].GetURL()
	})
	sort.Slice(a.InTheWild, func(i, j int) bool {
		return a.InTheWild[i].GetURL() < a.InTheWild[j].GetURL()
	})
	sort.Slice(a.Trickest, func(i, j int) bool {
		return a.Trickest[i].GetURL() < a.Trickest[j].GetURL()
	})
	sort.Slice(a.Nomisec, func(i, j int) bool {
		return a.Nomisec[i].GetURL() < a.Nomisec[j].GetURL()
	})
	sort.Slice(a.Nuclei, func(i, j int) bool {
		return a.Nuclei[i].GetURL() < a.Nuclei[j].GetURL()
	})
	sort.Slice(a.Openpoc, func(i, j int) bool {
		return a.Openpoc[i].URL < a.Openpoc[j].URL
	})
}

func (a *AggregatorResult) IsEmpty() bool {
	return len(a.Openpoc) == 0
}

func addToMerger[T OpenPocMetadata](exploit T, merger *map[string]*OpenpocProduct) {
	value, found := (*merger)[exploit.GetURL()]
	if !found {
		value = &OpenpocProduct{
			Cve:         exploit.GetCve(),
			URL:         exploit.GetURL(),
			AddedAt:     exploit.GetPublishDate().Format(time.RFC3339),
			TrustScore:  exploit.GetTrustScore(),
			TemplateFor: exploit.GetTemplateFor(),
		}
		(*merger)[exploit.GetURL()] = value
	} else {
		if exploit.GetTrustScore() > value.TrustScore {
			value.TrustScore = exploit.GetTrustScore()
		}
		// Ensure the date is the best we can find
		if value.AddedAt == DefaultDate.Format(time.RFC3339) {
			value.AddedAt = exploit.GetPublishDate().Format(time.RFC3339)
		} else {
			// We trust the date of the most trusted exploit
			if exploit.GetTrustScore() > value.TrustScore && exploit.GetPublishDate() != DefaultDate {
				value.AddedAt = exploit.GetPublishDate().Format(time.RFC3339)
			}
		}
	}
}
