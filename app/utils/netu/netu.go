package netu

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/cavaliercoder/grab"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/crypto"
)

// GetCIDRFromIpRange converts IP range to CIDR
func GetCIDRFromIpRange(ipRange string) (string, error) {
	if strings.Contains(ipRange, "-") {
		ipRangeS := strings.SplitN(ipRange, "-", 2)
		if len(ipRangeS) != 2 {
			return "", fmt.Errorf("Invalid IP range %s", ipRange)
		}
		ipA := net.ParseIP(ipRangeS[0])
		ipB := net.ParseIP(ipRangeS[1])
		maxLen := 32
		for l := maxLen; l >= 0; l-- {
			mask := net.CIDRMask(l, maxLen)
			na := ipA.Mask(mask)
			n := net.IPNet{IP: na, Mask: mask}
			if n.Contains(ipB) {
				return fmt.Sprintf("%v/%v", na, l), nil
			}
		}
	}
	return "", fmt.Errorf("Invalid IP range %s", ipRange)
}

// GetIpsFromCIDR gets IPs list from CIDR
func GetIpsFromCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIp(ip) {
		ips = append(ips, ip.String())
	}

	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

func incIp(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Get IPs list from range
func GetIpsFromIpRange(ipRange string) ([]string, error) {
	cidr, err := GetCIDRFromIpRange(ipRange)
	if err != nil {
		return nil, err
	}
	return GetIpsFromCIDR(cidr)
}

// DownloadFile downloads a file and display status
func DownloadFile(filename string, url string, hash string) error {
	if _, err := os.Stat(filename); err == nil {
		currentHash, err := crypto.HashFileSha256(filename)
		if err != nil {
			return err
		}
		if currentHash != hash {
			err := os.Remove(filename)
			if err != nil {
				return err
			}
		} else {
			return nil
		}
	}

	req, err := grab.NewRequest(url)
	if err != nil {
		return err
	}
	req.Filename = filename

	respch := grab.DefaultClient.DoAsync(req)
	resp := <-respch

	ticker := time.NewTicker(200 * time.Millisecond)
	for range ticker.C {
		if resp.IsComplete() {
			if resp.Error != nil {
				return resp.Error
			}
			break
		}
		fmt.Print(".")
	}

	ticker.Stop()
	return nil
}

// IsValidIPv4 validates an IPv4
func IsValidIPv4(ipAddress string) bool {
	ipAddress = strings.Trim(ipAddress, " ")
	re, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)
	if re.MatchString(ipAddress) {
		return true
	}
	return false
}

// GetIpFromReverse returns IP address from a reverse domain address
func GetIpFromReverse(domain string) string {
	re := regexp.MustCompile(`(?i)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	matches := re.FindStringSubmatch(domain)
	if len(matches) == 2 && IsValidIPv4(matches[1]) {
		return matches[1]
	}
	return ""
}
