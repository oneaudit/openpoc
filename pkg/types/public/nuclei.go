package public

import "time"

type Nuclei struct {
	CveID        string    `json:"cveId"`
	URL          string    `json:"url"`
	TemplatePath string    `json:"template_path"`
	AddedAt      time.Time `json:"added_at"`
}

func (n *Nuclei) GetCve() string {
	return n.CveID
}

func (n *Nuclei) GetURL() string {
	return n.URL
}

func (n *Nuclei) GetPublishDate() time.Time {
	return n.AddedAt
}

func (n *Nuclei) GetTrustScore() float64 {
	return 1.0
}

func (n *Nuclei) GetTemplateFor() string {
	return "nuclei"
}
