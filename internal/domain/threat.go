package domain

import "time"

type Threat struct {
	MD5         string    `json:"md5"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	ThreatType  string    `json:"threat_type"`
	Severity    string    `json:"severity"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
