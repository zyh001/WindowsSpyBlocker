package data

import (
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/crazy-max/WindowsSpyBlocker/app/bindata"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/config"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/netu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
	"github.com/pkg/errors"
)

// Systems, rules, types and exts constants
const (
	RULES_EXTRA  = "extra"
	RULES_SPY    = "spy"
	RULES_UPDATE = "update"

	TYPE_FIREWALL = "firewall"
	TYPE_HOSTS    = "hosts"

	EXT_DNSCRYPT   = "dnscrypt"
	EXT_ESET       = "eset"
	EXT_KASPERSKY  = "kaspersky"
	EXT_OPENWRT    = "openwrt"
	EXT_P2P        = "p2p"
	EXT_PROXIFIER  = "proxifier"
	EXT_SIMPLEWALL = "simplewall"
)

func getAsset(assetPath string) ([]string, error) {
	if config.App.UseEmbeddedData {
		return getAssetEmbbeded(assetPath)
	} else {
		return getAssetExternal(assetPath)
	}
}

func getAssetEmbbeded(assetPath string) ([]string, error) {
	result, err := bindata.Asset(assetPath)
	if err != nil {
		return []string{}, err
	}
	return strings.Split(string(result), "\n"), nil
}

func getAssetExternal(assetPath string) ([]string, error) {
	extPath := path.Join(pathu.Current, assetPath)
	if _, err := os.Stat(extPath); err != nil {
		return []string{}, errors.New(fmt.Sprintf("Cannot stat file: %s", strings.TrimLeft(extPath, pathu.Current)))
	}

	extFile, err := os.Open(extPath)
	if err != nil {
		return []string{}, errors.New(fmt.Sprintf("Cannot open file: %s", strings.TrimLeft(extPath, pathu.Current)))
	}
	defer extFile.Close()

	extFileBuf, err := os.ReadFile(extPath)
	if err != nil {
		return []string{}, errors.New(fmt.Sprintf("Cannot read file: %s", strings.TrimLeft(extPath, pathu.Current)))
	}

	return strings.Split(string(extFileBuf), "\n"), nil
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

// GetFirewallIps returns ips
func GetFirewallIps() (ips, error) {
	var result ips

	extra, err := GetFirewallIpsByRule(RULES_EXTRA)
	if err != nil {
		return result, err
	}
	result = append(result, extra...)

	spy, err := GetFirewallIpsByRule(RULES_SPY)
	if err != nil {
		return result, err
	}
	result = append(result, spy...)

	update, err := GetFirewallIpsByRule(RULES_UPDATE)
	if err != nil {
		return result, err
	}
	result = append(result, update...)

	sort.Sort(result)
	return result, nil
}

// GetFirewallIpsByRule returns ips filtered by rule
func GetFirewallIpsByRule(rule string) (ips, error) {
	var result ips

	rulesPath := path.Join("data", TYPE_FIREWALL, rule+".txt")
	lines, err := getAsset(rulesPath)
	if err != nil {
		return result, err
	}

	if len(lines) == 0 {
		return result, fmt.Errorf("No IPs found in %s", rulesPath)
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if netu.IsValidIpv4Range(line) || netu.IsValidIPv4(line) {
			result = append(result, ip{IP: line})
		}
	}

	sort.Sort(result)
	return result, nil
}

// GetHosts returns hosts
func GetHosts() (hosts, error) {
	var result hosts

	extra, err := GetHostsByRule(RULES_EXTRA)
	if err != nil {
		return result, err
	}
	result = append(result, extra...)

	spy, err := GetHostsByRule(RULES_SPY)
	if err != nil {
		return result, err
	}
	result = append(result, spy...)

	update, err := GetHostsByRule(RULES_UPDATE)
	if err != nil {
		return result, err
	}
	result = append(result, update...)

	sort.Sort(result)
	return result, nil
}

// GetHostsByRule returns hosts filtered by rule
func GetHostsByRule(rule string) (hosts, error) {
	var result hosts

	rulesPath := path.Join("data", TYPE_HOSTS, rule+".txt")
	lines, err := getAsset(rulesPath)
	if err != nil {
		return result, err
	}

	if len(lines) == 0 {
		return result, fmt.Errorf("No domains found in %s", rulesPath)
	}

	for _, line := range lines {
		line = strings.TrimRight(strings.Replace(strings.TrimSpace(line), "0.0.0.0 ", "", 1), ":443")
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		result = append(result, host{Domain: line})
	}

	sort.Sort(result)
	return result, nil
}

// GetExtIPs returns IPs for an external data filtered by rule
func GetExtIPs(ext string, rule string) (ips, error) {
	var err error
	var result ips

	if ext == EXT_ESET {
		result, err = getEsetIPs(rule)
		if err != nil {
			return nil, err
		}
	} else if ext == EXT_KASPERSKY {
		result, err = getKasperskyIPs(rule)
		if err != nil {
			return nil, err
		}
	} else if ext == EXT_OPENWRT {
		result, err = getOpenwrtIPs(rule)
		if err != nil {
			return nil, err
		}
	} else if ext == EXT_P2P {
		result, err = getP2pIPs(rule)
		if err != nil {
			return nil, err
		}
	} else if ext == EXT_PROXIFIER {
		result, err = getProxifierIPs(rule)
		if err != nil {
			return nil, err
		}
	} else if ext == EXT_SIMPLEWALL {
		result, err = getSimplewallIPs(rule)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// GetExtHosts returns hosts for an external data filtered by rule
func GetExtHosts(ext string, rule string) (hosts, error) {
	var err error
	var result hosts

	if ext == EXT_DNSCRYPT {
		result, err = getDnscryptHosts(rule)
		if err != nil {
			return nil, err
		}
	} else if ext == EXT_OPENWRT {
		result, err = getOpenwrtHosts(rule)
		if err != nil {
			return nil, err
		}
	} else if ext == EXT_PROXIFIER {
		result, err = getProxifierHosts(rule)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func getDnscryptHosts(rule string) (hosts, error) {
	var result hosts

	rulesPath := path.Join("data", EXT_DNSCRYPT, rule+".txt")
	lines, err := getAsset(rulesPath)
	if err != nil {
		return result, err
	}

	if len(lines) == 0 {
		return result, fmt.Errorf("No domains found in %s", rulesPath)
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		result = append(result, host{Domain: line})
	}

	sort.Sort(result)
	return result, nil
}

func getEsetIPs(rule string) (ips, error) {
	var result ips

	rulesPath := path.Join("data", EXT_ESET, rule+".txt")
	lines, err := getAsset(rulesPath)
	if err != nil {
		return result, err
	}

	if len(lines) == 0 {
		return result, fmt.Errorf("No IPs found in %s", rulesPath)
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimRight(line, ",")
		result = append(result, ip{IP: line})
	}

	sort.Sort(result)
	return result, nil
}

func getKasperskyIPs(rule string) (ips, error) {
	var result ips

	rulesPath := path.Join("data", EXT_KASPERSKY, rule+".txt")
	lines, err := getAsset(rulesPath)
	if err != nil {
		return result, err
	}

	if len(lines) == 0 {
		return result, fmt.Errorf("No IPs found in %s", rulesPath)
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimRight(line, ",")
		if strings.Contains(line, "/") {
			_, _, err := net.ParseCIDR(line)
			if err != nil {
				continue
			}
		}
		result = append(result, ip{IP: line})
	}

	sort.Sort(result)
	return result, nil
}

func getOpenwrtIPs(rule string) (ips, error) {
	var result ips

	rulesPath := path.Join("data", EXT_OPENWRT, rule, "firewall.user")
	lines, err := getAsset(rulesPath)
	if err != nil {
		return result, err
	}

	if len(lines) == 0 {
		return result, fmt.Errorf("No IPs found in %s", rulesPath)
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "iptables -I FORWARD -j DROP -d ") {
			continue
		}

		line = strings.TrimLeft(line, "iptables -I FORWARD -j DROP -d ")
		if strings.Contains(line, "/") {
			_, _, err := net.ParseCIDR(line)
			if err != nil {
				continue
			}
		}

		result = append(result, ip{IP: line})
	}

	sort.Sort(result)
	return result, nil
}

func getOpenwrtHosts(rule string) (hosts, error) {
	var result hosts

	rulesPath := path.Join("data", EXT_OPENWRT, rule, "dnsmasq.conf")
	lines, err := getAsset(rulesPath)
	if err != nil {
		return result, err
	}

	if len(lines) == 0 {
		return result, fmt.Errorf("No domains found in %s", rulesPath)
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "server=/") {
			continue
		}
		lineAr := strings.Split(line, "/")
		result = append(result, host{Domain: lineAr[1]})
	}

	sort.Sort(result)
	return result, nil
}

func getProxifierIPs(rule string) (ips, error) {
	var result ips

	rulesPath := path.Join("data", EXT_PROXIFIER, rule, "ips.txt")
	lines, err := getAsset(rulesPath)
	if err != nil {
		return result, err
	}

	if len(lines) == 0 {
		return result, fmt.Errorf("No IPs found in %s", rulesPath)
	}

	for _, line := range lines {
		line = strings.TrimRight(strings.TrimSpace(line), ";")
		result = append(result, ip{IP: line})
	}

	sort.Sort(result)
	return result, nil
}

func getProxifierHosts(rule string) (hosts, error) {
	var result hosts

	rulesPath := path.Join("data", EXT_PROXIFIER, rule, "domains.txt")
	lines, err := getAsset(rulesPath)
	if err != nil {
		return result, err
	}

	if len(lines) == 0 {
		return result, fmt.Errorf("No domains found in %s", rulesPath)
	}

	for _, line := range lines {
		line = strings.TrimRight(strings.TrimSpace(line), ";")
		result = append(result, host{Domain: line})
	}

	sort.Sort(result)
	return result, nil
}

func getSimplewallIPs(rule string) (ips, error) {
	var result ips

	rulesPath := path.Join("data", EXT_SIMPLEWALL, rule, "blocklist.xml")
	lines, err := getAsset(rulesPath)
	if err != nil {
		return result, err
	}
	rules, _ := bindata.Asset(rulesPath)

	if len(lines) == 0 {
		return result, fmt.Errorf("No IPs found in %s", rulesPath)
	}

	var root SimplewallRoot
	xml.Unmarshal(rules, &root)

	for _, item := range root.ItemList {
		result = append(result, ip{IP: item.rule})
	}

	sort.Sort(result)
	return result, nil
}

func getP2pIPs(rule string) (ips, error) {
	var result ips

	rulesPath := path.Join("data", EXT_P2P, rule+".txt")
	lines, err := getAsset(rulesPath)
	if err != nil {
		return result, err
	}

	if len(lines) == 0 {
		return result, fmt.Errorf("No IPs found in %s", rulesPath)
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "WindowsSpyBlocker:") {
			continue
		}
		ipRange := strings.TrimLeft(line, "WindowsSpyBlocker:")
		lineAr := strings.Split(ipRange, "-")
		if lineAr[0] == lineAr[1] {
			result = append(result, ip{IP: lineAr[0]})
		} else {
			result = append(result, ip{IP: ipRange})
		}
	}

	sort.Sort(result)
	return result, nil
}

// GetIPsSlice returns IPs as slice
func GetIPsSlice(resultIps ips) []string {
	var result []string

	for _, resultIp := range resultIps {
		result = append(result, resultIp.IP)
	}

	return result
}

// GetHostsSlice returns hosts as slice
func GetHostsSlice(resultHosts hosts) []string {
	var result []string

	for _, resultHost := range resultHosts {
		result = append(result, resultHost.Domain)
	}

	return result
}
