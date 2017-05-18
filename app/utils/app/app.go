package app

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/crazy-max/WindowsSpyBlocker/app/utils/config"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/file"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/netu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
	"github.com/crazy-max/WindowsSpyBlocker/app/whois"
)

// DownloadLib download an external library
func DownloadLib(lib config.Lib) error {
	if lib.OutputPath != "" {
		if _, err := os.Stat(lib.OutputPath); os.IsNotExist(err) {
			fmt.Printf("Creating folder %s... ", lib.OutputPath)
			if err := file.CreateSubfolder(lib.OutputPath); err != nil {
				print.Error(err)
				return err
			}
			print.Ok()
		}
		if _, err := os.Stat(lib.Checkfile); err != nil {
			fmt.Printf("Downloading %s...", lib.Url)
			if err := netu.DownloadFile(lib.Dest, lib.Url, lib.Checksum); err != nil {
				fmt.Print(" ")
				print.Error(err)
				return err
			}
			fmt.Print(" ")
			print.Ok()

			fmt.Printf("Unzipping %s... ", lib.Dest)
			if err := file.Unzip(lib.Dest, lib.OutputPath); err != nil {
				print.Error(err)
				return err
			}
			print.Ok()

			fmt.Printf("Seeking checkfile %s... ", lib.Checkfile)
			if _, err := os.Stat(lib.Checkfile); err != nil {
				print.Error(err)
				return err
			}
			print.Ok()
		}
	} else {
		fmt.Printf("Downloading %s...", lib.Url)
		if err := netu.DownloadFile(lib.Dest, lib.Url, lib.Checksum); err != nil {
			fmt.Print(" ")
			print.Error(err)
			return err
		}
		fmt.Print(" ")
		print.Ok()
	}

	return nil
}

// GetFilteredIpOrDomain get an ip address or domain filtered by excluded values in app.conf
func GetFilteredIpOrDomain(ipOrDomain string) string {
	ipOrDomain = strings.ToLower(ipOrDomain)

	if netu.IsValidIPv4(ipOrDomain) {
		for _, exp := range config.App.Exclude.Ips {
			if isIpExcluded(ipOrDomain, exp) {
				return ""
			}
		}
	} else {
		for _, exp := range config.App.Exclude.Hosts {
			if isDomainExcluded(ipOrDomain, exp) {
				return ""
			}
		}
	}

	whoisRes := whois.GetWhois(ipOrDomain)
	if whoisRes != (whois.Whois{}) {
		for _, exp := range config.App.Exclude.Orgs {
			if isOrgExcluded(whoisRes.Org, exp) {
				return ""
			}
		}
	}

	return ipOrDomain
}

func isIpExcluded(ipStr string, exp string) bool {
	ip := net.ParseIP(ipStr)
	if ip.To4() == nil {
		return true
	}

	if strings.Contains(exp, "-") {
		ipRange := strings.SplitN(exp, "-", 2)
		if len(ipRange) != 2 {
			return false
		}
		ipRange0 := net.ParseIP(ipRange[0])
		ipRange1 := net.ParseIP(ipRange[1])
		if ipRange0.To4() == nil || ipRange1.To4() == nil {
			return false
		}
		if bytes.Compare(ip, ipRange0) >= 0 && bytes.Compare(ip, ipRange1) <= 0 {
			//fmt.Println(host + " in range of " + ipEx)
			return true
		}
	} else if !netu.IsValidIPv4(exp) {
		return false
	} else if exp == ipStr {
		//fmt.Println(host + " = " + ipEx)
		return true
	}

	return false
}

func isDomainExcluded(host string, exp string) bool {
	re := regexp.MustCompile(`(?i)^` + strings.Replace(exp, "*", "(.*?)", -1) + "$")
	matches := re.FindAllString(host, -1)
	if len(matches) == 1 {
		return true
	}
	return false
}

func isOrgExcluded(org string, exp string) bool {
	re := regexp.MustCompile(`(?i)^` + strings.Replace(exp, "*", "(.*?)", -1) + "$")
	matches := re.FindAllString(org, -1)
	if len(matches) == 1 {
		return true
	}
	return false
}
