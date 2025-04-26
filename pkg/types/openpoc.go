package types

import "time"

// Ensure we don't have more than what the RFC3339 when using .String()
var DefaultDate, _ = time.Parse(time.DateOnly, time.Unix(0, 0).Format(time.DateOnly))

type OpenPocMetadata interface {
	GetCve() string
	GetURL() string
	GetPublishDate() time.Time
	GetTrustScore() float64
}

type OpenpocProduct struct {
	Cve        string  `json:"cve"`
	URL        string  `json:"url"`
	AddedAt    string  `json:"added_at"`
	TrustScore float64 `json:"trust_score"`
}
