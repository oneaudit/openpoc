package types

import (
	providertypes "openpoc/pkg/types/public"
	"sort"
	"time"
)

type AggregatorResult struct {
	ExploitDB  []*providertypes.ExploitDB  `json:"exploitdb"`
	InTheWild  []*providertypes.InTheWild  `json:"itw"`
	Trickest   []*providertypes.Trickest   `json:"trickest"`
	Nomisec    []*providertypes.Nomisec    `json:"nomisec"`
	Nuclei     []*providertypes.Nuclei     `json:"nuclei"`
	Metasploit []*providertypes.Metasploit `json:"metasploit"`
	Holloways  []*providertypes.Holloways  `json:"holloways"`
	Openpoc    []*OpenpocProduct           `json:"openpoc"`
}

func NewAggregatorResult() *AggregatorResult {
	return &AggregatorResult{
		InTheWild:  []*providertypes.InTheWild{},
		ExploitDB:  []*providertypes.ExploitDB{},
		Trickest:   []*providertypes.Trickest{},
		Nomisec:    []*providertypes.Nomisec{},
		Nuclei:     []*providertypes.Nuclei{},
		Metasploit: []*providertypes.Metasploit{},
		Holloways:  []*providertypes.Holloways{},
		Openpoc:    []*OpenpocProduct{},
	}
}

func (a *AggregatorResult) ComputeOpenPoc() {
	merger := make(map[string]*OpenpocProduct)
	for _, exploit := range a.Trickest { // dirty, first
		addToMerger(exploit, &merger)
	}
	for _, exploit := range a.InTheWild { // dirty too, second
		addToMerger(exploit, &merger)
	}
	for _, exploit := range a.ExploitDB { // good, third
		addToMerger(exploit, &merger)
	}
	for _, exploit := range a.Nomisec { // the best, fourth
		addToMerger(exploit, &merger)
	}
	for _, exploit := range a.Nuclei { // fifth, no impact
		addToMerger(exploit, &merger)
	}
	for _, exploit := range a.Metasploit { // sixth, no impact
		addToMerger(exploit, &merger)
	}
	for _, exploit := range a.Holloways { // seventh, may impact but trusted
		addToMerger(exploit, &merger)
	}
	for _, url := range merger {
		a.Openpoc = append(a.Openpoc, url)
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
	sort.Slice(a.Metasploit, func(i, j int) bool {
		return a.Metasploit[i].GetURL() < a.Metasploit[j].GetURL()
	})
	sort.Slice(a.Holloways, func(i, j int) bool {
		return a.Holloways[i].GetURL() < a.Holloways[j].GetURL()
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
			AddedAt:     exploit.GetPublishDate().Format(timeFormat),
			TrustScore:  exploit.GetTrustScore(),
			TemplateFor: exploit.GetTemplateFor(),
		}
		(*merger)[exploit.GetURL()] = value
	} else {
		if exploit.GetTrustScore() > value.TrustScore {
			value.TrustScore = exploit.GetTrustScore()
		}
		if exploit.GetPublishDate() == DefaultDate {
			return
		}

		// Ensure the date is the best we can find
		if value.AddedAt == DefaultDate.Format(timeFormat) {
			value.AddedAt = exploit.GetPublishDate().Format(timeFormat)
		} else {
			var valueAddedAt, _ = time.Parse(timeFormat, value.AddedAt)
			if exploit.GetPublishDate().Before(valueAddedAt) {
				value.AddedAt = exploit.GetPublishDate().Format(timeFormat)
			}
		}
	}
}
