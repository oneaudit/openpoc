package types

import "time"

type Nomisec struct {
	CveId               string          `json:"cveId"`
	ID                  int             `json:"id"`
	Name                string          `json:"name"`
	FullName            string          `json:"full_name"`
	Owner               RepositoryOwner `json:"owner"`
	HTMLURL             string          `json:"html_url"`
	Description         string          `json:"description"`
	Fork                bool            `json:"fork"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
	PushedAt            time.Time       `json:"pushed_at"`
	StargazersCount     int             `json:"stargazers_count"`
	WatchersCount       int             `json:"watchers_count"`
	HasDiscussions      bool            `json:"has_discussions"`
	ForksCount          int             `json:"forks_count"`
	AllowForking        bool            `json:"allow_forking"`
	IsTemplate          bool            `json:"is_template"`
	WebCommitSignoffReq bool            `json:"web_commit_signoff_required"`
	Topics              []string        `json:"topics"`
	Visibility          string          `json:"visibility"`
	Forks               int             `json:"forks"`
	Watchers            int             `json:"watchers"`
	Score               int             `json:"score"`
	SubscribersCount    int             `json:"subscribers_count"`
}

type RepositoryOwner struct {
	Login        string `json:"login"`
	ID           int    `json:"id"`
	AvatarURL    string `json:"avatar_url"`
	HTMLURL      string `json:"html_url"`
	UserViewType string `json:"user_view_type"`
}

func (n *Nomisec) GetCve() string {
	return n.CveId
}

func (n *Nomisec) GetURL() string {
	return n.HTMLURL
}

func (n *Nomisec) GetPublishDate() time.Time {
	return n.CreatedAt
}

func (n *Nomisec) GetTrustScore() float64 {
	// Having a lot of stars means it is somewhat trustworthy?
	if n.StargazersCount > 1000 {
		return 1.0
	}
	return float64(n.StargazersCount) / 1000.0
}
