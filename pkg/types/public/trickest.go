package public

import (
	"strings"
	"time"
)

type Trickest struct {
	CveID   string    `json:"id"`
	URL     string    `json:"url"`
	AddedAt time.Time `json:"added_at"`
	Score   float64   `json:"-"`
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

func (t *Trickest) GetTrustScore() float64 {
	return t.Score
}

func (t *Trickest) GetTemplateFor() string {
	return IsTemplateForURL(t.GetURL())
}

func IsTemplateForURL(url string) string {
	if strings.HasPrefix(url, "https://seclists.org/fulldisclosure/") {
		return "nmap"
	}
	return ""
}
