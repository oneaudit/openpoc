package types

type InTheWild struct {
	CveID        string `json:"id"`
	Description  string `json:"description"`
	ReferenceURL string `json:"referenceURL"`
	ReportURL    string `json:"reportURL"`
	Timestamp    string `json:"timeStamp"`
}

func (i *InTheWild) GetCve() string {
	return i.CveID
}

func (i *InTheWild) GetURL() string {
	return i.ReportURL
}

func (i *InTheWild) AddedAt() string {
	return i.Timestamp
}

func (i *InTheWild) IsTrustworthy() bool {
	return true
}
