package wireshark

import (
	"bytes"
	"net"

	"github.com/crazy-max/WindowsSpyBlocker/app/dnsres"
	"github.com/crazy-max/WindowsSpyBlocker/app/whois"
)

// Event of Wireshark
type Event struct {
	IP     string             `json:"ip"`
	Count  int                `json:"count"`
	DnsRes dnsres.Resolutions `json:"dnsres"`
	Whois  whois.Whois        `json:"whois"`
}

// Events of Wireshark sorted by IP
type Events []Event

func (slice Events) Len() int {
	return len(slice)
}

func (slice Events) Less(i, j int) bool {
	ipA := net.ParseIP(slice[i].IP)
	ipB := net.ParseIP(slice[j].IP)
	switch bytes.Compare(ipA, ipB) {
	case -1:
		return true
	case 0, 1:
		return false
	default:
		return false
	}
}

func (slice Events) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}
