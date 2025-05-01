package public

import "time"

type Holloways struct {
	CveID   string    `json:"cve"`
	URL     string    `json:"url"`
	AddedAt time.Time `json:"addedAt"`
	Score   float64   `json:"score"`
}

func (h *Holloways) GetCve() string {
	return h.CveID
}

func (h *Holloways) GetURL() string {
	return h.URL
}

func (h *Holloways) GetPublishDate() time.Time {
	return h.AddedAt
}

func (h *Holloways) GetTrustScore() float64 {
	return 1.0
}

func (h *Holloways) GetTemplateFor() string {
	return "nuclei"
}
