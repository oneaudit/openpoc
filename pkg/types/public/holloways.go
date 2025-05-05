package public

import "time"

type Holloways struct {
	Cve         string    `json:"cve"`
	URL         string    `json:"url"`
	AddedAt     time.Time `json:"added_at"`
	TrustScore  float64   `json:"score"`
	TemplateFor string    `json:"template_for"`
}

func (h *Holloways) GetCve() string {
	return h.Cve
}

func (h *Holloways) GetURL() string {
	return h.URL
}

func (h *Holloways) GetPublishDate() time.Time {
	return h.AddedAt
}

func (h *Holloways) GetTrustScore() float64 {
	return h.TrustScore
}

func (h *Holloways) GetTemplateFor() string {
	return h.TemplateFor
}
