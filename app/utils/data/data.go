package data

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"path"
	"sort"
	"strings"

	"github.com/crazy-max/WindowsSpyBlocker/app/bindata"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/netu"
)

const (
	FIREWALL = "data/firewall/"
	HOSTS    = "data/hosts/"

	OS_WIN7  = "win7"
	OS_WIN81 = "win81"
	OS_WIN10 = "win10"

	RULES_EXTRA  = "extra"
	RULES_SPY    = "spy"
	RULES_UPDATE = "update"
)

type FirewallIp struct {
	IP string `json:"ip"`
}

type Host struct {
	Domain string `json:"domain"`
}

type FirewallIps []FirewallIp
type Hosts []Host

func (slice FirewallIps) Len() int {
	return len(slice)
}

func (slice FirewallIps) Less(i, j int) bool {
	ipA := net.ParseIP(getIp(slice[i].IP))
	ipB := net.ParseIP(getIp(slice[j].IP))
	switch bytes.Compare(ipA, ipB) {
	case -1:
		return true
	case 0, 1:
		return false
	default:
		return false
	}
}

func (slice FirewallIps) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (slice Hosts) Len() int {
	return len(slice)
}

func (slice Hosts) Less(i, j int) bool {
	return slice[i].Domain < slice[j].Domain
}

func (slice Hosts) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func getAsset(path string) ([]string, error) {
	result, err := bindata.Asset(path)
	if err != nil {
		return []string{}, err
	}
	return strings.Split(string(result), "\n"), nil
}

func getIp(ip string) string {
	if strings.Contains(ip, "-") {
		ipRange := strings.SplitN(ip, "-", 2)
		if len(ipRange) != 2 {
			return ip
		}
		if !netu.IsValidIPv4(ipRange[0]) {
			return ip
		}
		return ipRange[0]
	}
	return ip
}

func GetFirewallIps(system string) (FirewallIps, error) {
	var ips FirewallIps

	extra, err := GetFirewallIpsByRule(system, RULES_EXTRA)
	if err != nil {
		return ips, err
	}
	ips = append(ips, extra...)

	spy, err := GetFirewallIpsByRule(system, RULES_SPY)
	if err != nil {
		return ips, err
	}
	ips = append(ips, spy...)

	update, err := GetFirewallIpsByRule(system, RULES_UPDATE)
	if err != nil {
		return ips, err
	}
	ips = append(ips, update...)

	sort.Sort(ips)
	return ips, nil
}

func GetFirewallIpsByRule(system string, rule string) (FirewallIps, error) {
	var ips FirewallIps

	rulesPath := path.Join(FIREWALL, system, rule+".txt")
	lines, err := getAsset(rulesPath)
	if err != nil {
		return ips, err
	}

	if len(lines) == 0 {
		return ips, errors.New(fmt.Sprintf("No IPs found in %s", rulesPath))
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.Contains(line, "-") {
			ipRange := strings.SplitN(line, "-", 2)
			if len(ipRange) != 2 {
				continue
			}
			if !netu.IsValidIPv4(ipRange[0]) || !netu.IsValidIPv4(ipRange[1]) {
				continue
			}
			ips = append(ips, FirewallIp{IP: line})
		} else if netu.IsValidIPv4(line) {
			ips = append(ips, FirewallIp{IP: line})
		}
	}

	sort.Sort(ips)
	return ips, nil
}

func GetHosts(system string) (Hosts, error) {
	var hosts Hosts

	extra, err := GetHostsByRule(system, RULES_EXTRA)
	if err != nil {
		return hosts, err
	}
	hosts = append(hosts, extra...)

	spy, err := GetHostsByRule(system, RULES_SPY)
	if err != nil {
		return hosts, err
	}
	hosts = append(hosts, spy...)

	update, err := GetHostsByRule(system, RULES_UPDATE)
	if err != nil {
		return hosts, err
	}
	hosts = append(hosts, update...)

	sort.Sort(hosts)
	return hosts, nil
}

func GetHostsByRule(system string, rule string) (Hosts, error) {
	var hosts Hosts

	rulesPath := path.Join(HOSTS, system, rule+".txt")
	lines, err := getAsset(rulesPath)
	if err != nil {
		return hosts, err
	}

	if len(lines) == 0 {
		return hosts, errors.New(fmt.Sprintf("No domains found in %s", rulesPath))
	}

	for _, line := range lines {
		line = strings.Replace(strings.TrimSpace(line), "0.0.0.0 ", "", -1)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		hosts = append(hosts, Host{Domain: line})
	}

	sort.Sort(hosts)
	return hosts, nil
}
