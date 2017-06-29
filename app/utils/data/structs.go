package data

import (
	"bytes"
	"net"
	"strings"

	"github.com/crazy-max/WindowsSpyBlocker/app/utils/netu"
)

type ip struct {
	IP string `json:"ip"`
}

type ips []ip

func (slice ips) Len() int {
	return len(slice)
}

func (slice ips) Less(i, j int) bool {
	ipA := net.ParseIP(slice[i].IP)
	if netu.IsValidIpv4Range(slice[i].IP) {
		if ipsRange, err := netu.GetIpsFromIPRange(slice[i].IP); err == nil {
			ipA = net.ParseIP(ipsRange[0])
		}
	} else if strings.Contains(slice[i].IP, "/") {
		if ipsCidr, err := netu.GetIpsFromCIDR(slice[i].IP); err == nil {
			ipA = net.ParseIP(ipsCidr[0])
		}
	}
	ipB := net.ParseIP(slice[j].IP)
	if netu.IsValidIpv4Range(slice[j].IP) {
		if ipsRange, err := netu.GetIpsFromIPRange(slice[j].IP); err == nil {
			ipB = net.ParseIP(ipsRange[0])
		}
	} else if strings.Contains(slice[j].IP, "/") {
		if ipsCidr, err := netu.GetIpsFromCIDR(slice[j].IP); err == nil {
			ipB = net.ParseIP(ipsCidr[0])
		}
	}

	switch bytes.Compare(ipA, ipB) {
	case -1:
		return true
	case 0, 1:
		return false
	default:
		return false
	}
}

func (slice ips) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

type hosts []host

func (slice hosts) Len() int {
	return len(slice)
}

type host struct {
	Domain string `json:"domain"`
}

func (slice hosts) Less(i, j int) bool {
	return slice[i].Domain < slice[j].Domain
}

func (slice hosts) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

type SimplewallRoot struct {
	ItemList []SimplewallItem `xml:"item>"`
}

type SimplewallItem struct {
	name       string
	rule       string
	dir        int
	protocol   int
	version    string
	is_block   int
	is_enabled int
}
