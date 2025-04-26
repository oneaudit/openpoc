package types

import (
	"encoding/json"
	"time"
)

type InTheWild struct {
	CveID        string    `json:"id"`
	Description  string    `json:"description"`
	ReferenceURL string    `json:"referenceURL"`
	ReportURL    string    `json:"reportURL"`
	Timestamp    Timestamp `json:"timeStamp"`
	Trustworthy  bool      `json:"-"`
}

type Timestamp time.Time

func (i *InTheWild) GetCve() string {
	return i.CveID
}

func (i *InTheWild) GetURL() string {
	return i.ReportURL
}

func (i *InTheWild) GetPublishDate() time.Time {
	return time.Time(i.Timestamp)
}

func (i *InTheWild) GetTrustScore() float64 {
	if i.Trustworthy {
		return 0.5
	}
	return 0.0
}

func (t *Timestamp) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339, s)
	if err == nil {
		*t = Timestamp(parsed)
		return nil
	}
	parsed, err = time.Parse(time.DateOnly, s)
	if err == nil {
		*t = Timestamp(parsed)
		return nil
	}
	return err
}

func (t *Timestamp) MarshalJSON() ([]byte, error) {
	lt := time.Time(*t)
	return json.Marshal(lt)
}
