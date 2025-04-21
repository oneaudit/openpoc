package types

type OpenPocMetadata interface {
	GetCve() string
	GetURL() string
	GetPublishDate() string
	IsTrustworthy() bool
}

type OpenpocProduct struct {
	Cve         string `json:"cve"`
	URL         string `json:"url"`
	AddedAt     string `json:"added_at"`
	Trustworthy bool   `json:"trustworthy"`
}
