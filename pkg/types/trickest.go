package types

import "time"

type Trickest struct {
	CveID       string    `json:"id"`
	URL         string    `json:"url"`
	AddedAt     time.Time `json:"added_at"`
	Trustworthy bool      `json:"trustworthy"`
}

func (t *Trickest) GetCve() string {
	return t.CveID
}

func (t *Trickest) GetURL() string {
	return t.URL
}

func (t *Trickest) GetPublishDate() time.Time {
	return t.AddedAt
}

func (t *Trickest) IsTrustworthy() bool {
	return t.Trustworthy
}
