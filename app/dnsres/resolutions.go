package dnsres

import (
	"time"
)

// Resolution structure
type Resolution struct {
	Source       string
	LastResolved time.Time
	IpOrDomain   string
}

// Resolutions structure sorted by LastResolved
type Resolutions []Resolution

func (slice Resolutions) Len() int {
	return len(slice)
}

func (slice Resolutions) Less(i, j int) bool {
	return slice[i].LastResolved.After(slice[j].LastResolved)
}

func (slice Resolutions) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}
