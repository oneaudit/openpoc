package types

import "time"

type Nuclei struct {
}

func (n *Nuclei) GetCve() string {
	return ""
}

func (n *Nuclei) GetURL() string {
	return ""
}

func (n *Nuclei) GetPublishDate() time.Time {
	return time.Now()
}

func (n *Nuclei) GetTrustScore() float64 {
	return 0
}

func (n *Nuclei) GetTemplateFor() string {
	return "nuclei"
}
