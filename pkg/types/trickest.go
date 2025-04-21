package types

type Trickest struct {
	CveID       string `json:"id"`
	URL         string `json:"url"`
	AddedAt     string `json:"added_at"`
	Trustworthy bool   `json:"trustworthy"`
}

func (t *Trickest) GetCve() string {
	return t.CveID
}

func (t *Trickest) GetURL() string {
	return t.URL
}

func (t *Trickest) GetPublishDate() string {
	return t.AddedAt
}

func (t *Trickest) IsTrustworthy() bool {
	return t.Trustworthy
}
