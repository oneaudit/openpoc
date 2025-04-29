package public

import "time"

type Metasploit struct {
	CveID        string    `json:"cveId"`
	URL          string    `json:"url"`
	TemplatePath string    `json:"template_path"`
	AddedAt      time.Time `json:"added_at"`
}

func (m *Metasploit) GetCve() string {
	return m.CveID
}

func (m *Metasploit) GetURL() string {
	return m.URL
}

func (m *Metasploit) GetPublishDate() time.Time {
	return m.AddedAt
}

func (m *Metasploit) GetTrustScore() float64 {
	return 1.0
}

func (m *Metasploit) GetTemplateFor() string {
	return "metasploit"
}
