package data

import (
	"fmt"
	"net"
	"path"
	"sort"
	"strings"

	"github.com/crazy-max/WindowsSpyBlocker/app/bindata"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/netu"
)

// Systems, rules, types and exts constants
const (
	OS_WIN7  = "win7"
	OS_WIN81 = "win81"
	OS_WIN10 = "win10"

	RULES_EXTRA  = "extra"
	RULES_SPY    = "spy"
	RULES_UPDATE = "update"

	TYPE_FIREWALL = "firewall"
	TYPE_HOSTS    = "hosts"

	EXT_DNSCRYPT  = "dnscrypt"
	EXT_OPENWRT   = "openwrt"
	EXT_PROXIFIER = "proxifier"

	DNSCRYPT_HEAD  = ""
	DNSCRYPT_VALUE = "%s"

	OPENWRT_IP_HEAD = `### openwrt %s %s (/etc/firewall.user)
### More info: %s

# enforce router DNS
iptables -t nat -I PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports 53
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 53

# rules
`
	OPENWRT_IP_VALUE     = "iptables -I FORWARD -j DROP -d %s"
	OPENWRT_DOMAINS_HEAD = `### openwrt %s %s (/etc/dnsmasq.conf)
### More info: %s

`
	OPENWRT_DOMAINS_VALUE = "server=/%s/"

	PROXIFIER_IP_HEAD       = ""
	PROXIFIER_IP_VALUE      = "%s;"
	PROXIFIER_DOMAINS_HEAD  = ""
	PROXIFIER_DOMAINS_VALUE = "%s;"
)

// WilcardSubdomains are wildcard of domains for DNSCrypt and Proxifier
var WilcardSubdomains []string

func init() {
	WilcardSubdomains = []string{
		"*.2mdn.net",
		"*.a-msedge.net",
		"*.adnexus.net",
		"*.adnxs.com",
		"*.ads*.msads.net",
		"*.ads*.msn.com",
		"*.ams*.msecn.net",
		"*.appex-rf.msn.com",
		"*.atdmt.com",
		"*.dc-msedge.net",
		"*.delivery.dsp.mp.microsoft.com.nsatc.net",
		"*.delivery.mp.microsoft.com",
		"*.glbdns2.microsoft.com",
		"*.location.live.net",
		"*.messenger.live.com",
		"*.microsoftwindowsupdate.net",
		"*.msedge.net",
		"*.msftncsi.com",
		"*.rad.live.com",
		"*.rad.msn.com",
		"*.rads.msn.com",
		"*.services.appex.bing.com",
		"*.services.social.microsoft.com",
		"*.smartscreen.microsoft.com",
		"*.telemetry.appex.bing.net",
		"*.telemetry.microsoft.com",
		"*.telemetry.microsoft.com.nsatc.net",
		"*.telemetry.urs.microsoft.com",
		"*.tile.appex.bing.com",
		"*.trafficmanager.net",
		"*.update.microsoft.com",
		"*.update.microsoft.com.akadns.net",
		"*.virtualearth.net",
		"*.vo.msecnd.net",
		"*.vortex*.data.metron.live.com.nsatc.net",
		"*.vortex*.data.microsoft.com",
		"*.vortex.data.microsoft.com",
		"*.weather.microsoft.com",
		"*.windowsupdate.com",
		"*.windowsupdate.org",
		"*.windowupdate.org",
		"*.ws.microsoft.com",
		"*.xboxlive.com",
		"array*-prod.do.dsp.mp.microsoft.com",
		"vortex-*.metron.live.com.nsatc.net",
	}
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

// GetFirewallIps returns ips filtered by system
func GetFirewallIps(system string) (ips, error) {
	var result ips

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

// GetFirewallIpsByRule returns ips filtered by system and rule
func GetFirewallIpsByRule(system string, rule string) (ips, error) {
	var result ips

	rulesPath := path.Join("data", TYPE_FIREWALL, system, rule+".txt")
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

	rulesPath := path.Join("data", TYPE_HOSTS, system, rule+".txt")
	lines, err := getAsset(rulesPath)
	if err != nil {
		return result, err
	}

	if len(lines) == 0 {
		return result, fmt.Errorf("No domains found in %s", rulesPath)
	}

	for _, line := range lines {
		line = strings.TrimRight(strings.TrimLeft(strings.TrimSpace(line), "0.0.0.0 "), ":443")
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		result = append(result, host{Domain: line})
	}

	sort.Sort(result)
	return result, nil
}

// GetExtIPs returns IPs for an external data filtered by system and rule
func GetExtIPs(ext string, system string, rule string) (ips, error) {
	var err error
	var result ips

	if ext == EXT_OPENWRT {
		result, err = getOpenwrtIPs(system, rule)
		if err != nil {
			return nil, err
		}
	} else if ext == EXT_PROXIFIER {
		result, err = getProxifierIPs(system, rule)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// GetExtHosts returns hosts for an external data filtered by system and rule
func GetExtHosts(ext string, system string, rule string) (hosts, error) {
	var err error
	var result hosts

	if ext == EXT_DNSCRYPT {
		result, err = getDnscryptHosts(system, rule)
		if err != nil {
			return nil, err
		}
	} else if ext == EXT_OPENWRT {
		result, err = getOpenwrtHosts(system, rule)
		if err != nil {
			return nil, err
		}
	} else if ext == EXT_PROXIFIER {
		result, err = getProxifierHosts(system, rule)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func getDnscryptHosts(system string, rule string) (hosts, error) {
	var result hosts

	rulesPath := path.Join("data", EXT_DNSCRYPT, system, rule+".txt")
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

func getOpenwrtIPs(system string, rule string) (ips, error) {
	var result ips

	rulesPath := path.Join("data", EXT_OPENWRT, system, rule, "firewall.user")
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

func getOpenwrtHosts(system string, rule string) (hosts, error) {
	var result hosts

	rulesPath := path.Join("data", EXT_OPENWRT, system, rule, "dnsmasq.conf")
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

func getProxifierIPs(system string, rule string) (ips, error) {
	var result ips

	rulesPath := path.Join("data", EXT_PROXIFIER, system, rule, "ips.txt")
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

func getProxifierHosts(system string, rule string) (hosts, error) {
	var result hosts

	rulesPath := path.Join("data", EXT_PROXIFIER, system, rule, "domains.txt")
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
