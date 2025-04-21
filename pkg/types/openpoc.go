package types

type OpenpocProduct struct {
	Cve         string `json:"cve"`
	URL         string `json:"url"`
	AddedAt     string `json:"added_at"`
	Trustworthy bool   `json:"trustworthy"`
}
