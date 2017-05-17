package proxifier

import (
	"bytes"
	"net"
	"time"

	"github.com/crazy-max/WindowsSpyBlocker/app/utils/netu"
	"github.com/crazy-max/WindowsSpyBlocker/app/whois"
)

// Event of Proxifier
type Event struct {
	Date    time.Time   `json:"date"`
	Exe     string      `json:"exe"`
	Pid     int         `json:"pid"`
	Account string      `json:"account"`
	Host    string      `json:"host"`
	Whois   whois.Whois `json:"whois"`
	Count   int         `json:"count"`
}

// EventsSortHost of Proxifier sorted by Host
type EventsSortHost []Event

// EventsSortDate of Proxifier sorted by Date
type EventsSortDate []Event

func (slice EventsSortHost) Len() int {
	return len(slice)
}

func (slice EventsSortHost) Less(i, j int) bool {
	hostA := []byte(slice[i].Host)
	if netu.IsValidIPv4(slice[i].Host) {
		hostA = net.ParseIP(slice[i].Host)
	}
	hostB := []byte(slice[j].Host)
	if netu.IsValidIPv4(slice[j].Host) {
		hostB = net.ParseIP(slice[j].Host)
	}
	switch bytes.Compare(hostA, hostB) {
	case -1:
		return true
	case 0, 1:
		return false
	default:
		return false
	}
}

func (slice EventsSortHost) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (slice EventsSortDate) Len() int {
	return len(slice)
}

func (slice EventsSortDate) Less(i, j int) bool {
	return slice[i].Date.Before(slice[j].Date)
}

func (slice EventsSortDate) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}
