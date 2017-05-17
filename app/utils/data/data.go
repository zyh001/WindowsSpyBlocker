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

// Data system and rules constants
const (
	OS_WIN7  = "win7"
	OS_WIN81 = "win81"
	OS_WIN10 = "win10"

	RULES_EXTRA  = "extra"
	RULES_SPY    = "spy"
	RULES_UPDATE = "update"
)

type firewallIp struct {
	IP string `json:"ip"`
}

type host struct {
	Domain string `json:"domain"`
}

type firewallIps []firewallIp
type hosts []host

func (slice firewallIps) Len() int {
	return len(slice)
}

func (slice firewallIps) Less(i, j int) bool {
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

func (slice firewallIps) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (slice hosts) Len() int {
	return len(slice)
}

func (slice hosts) Less(i, j int) bool {
	return slice[i].Domain < slice[j].Domain
}

func (slice hosts) Swap(i, j int) {
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

// GetFirewallIps returns firewallIps filtered by system
func GetFirewallIps(system string) (firewallIps, error) {
	var result firewallIps

	extra, err := GetFirewallIpsByRule(system, RULES_EXTRA)
	if err != nil {
		return result, err
	}
	result = append(result, extra...)

	spy, err := GetFirewallIpsByRule(system, RULES_SPY)
	if err != nil {
		return result, err
	}
	result = append(result, spy...)

	update, err := GetFirewallIpsByRule(system, RULES_UPDATE)
	if err != nil {
		return result, err
	}
	result = append(result, update...)

	sort.Sort(result)
	return result, nil
}

// GetFirewallIpsByRule returns firewallIps filtered by system and rule
func GetFirewallIpsByRule(system string, rule string) (firewallIps, error) {
	var result firewallIps

	rulesPath := path.Join("data/firewall/", system, rule+".txt")
	lines, err := getAsset(rulesPath)
	if err != nil {
		return result, err
	}

	if len(lines) == 0 {
		return result, errors.New(fmt.Sprintf("No IPs found in %s", rulesPath))
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
			result = append(result, firewallIp{IP: line})
		} else if netu.IsValidIPv4(line) {
			result = append(result, firewallIp{IP: line})
		}
	}

	sort.Sort(result)
	return result, nil
}

// GetHosts returns hosts filtered by system
func GetHosts(system string) (hosts, error) {
	var result hosts

	extra, err := GetHostsByRule(system, RULES_EXTRA)
	if err != nil {
		return result, err
	}
	result = append(result, extra...)

	spy, err := GetHostsByRule(system, RULES_SPY)
	if err != nil {
		return result, err
	}
	result = append(result, spy...)

	update, err := GetHostsByRule(system, RULES_UPDATE)
	if err != nil {
		return result, err
	}
	result = append(result, update...)

	sort.Sort(result)
	return result, nil
}

// GetHostsByRule returns hosts filtered by system and rule
func GetHostsByRule(system string, rule string) (hosts, error) {
	var result hosts

	rulesPath := path.Join("data/hosts/", system, rule+".txt")
	lines, err := getAsset(rulesPath)
	if err != nil {
		return result, err
	}

	if len(lines) == 0 {
		return result, errors.New(fmt.Sprintf("No domains found in %s", rulesPath))
	}

	for _, line := range lines {
		line = strings.Replace(strings.TrimSpace(line), "0.0.0.0 ", "", -1)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		result = append(result, host{Domain: line})
	}

	sort.Sort(result)
	return result, nil
}
