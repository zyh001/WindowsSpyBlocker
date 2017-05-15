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

func DownloadLib(lib config.Lib) error {
	if _, err := os.Stat(lib.Path); os.IsNotExist(err) {
		fmt.Printf("Creating folder %s... ", lib.Path)
		if err := file.CreateSubfolder(lib.Path); err != nil {
			print.Error(err)
			return err
		} else {
			print.Ok()
		}
	}

	if _, err := os.Stat(lib.Executable); err != nil {
		fmt.Printf("Downloading %s...", lib.Url)
		if err := netu.DownloadFile(lib.Zip, lib.Url, lib.Checksum); err != nil {
			fmt.Print(" ")
			print.Error(err)
			return err
		} else {
			fmt.Print(" ")
			print.Ok()
		}

		fmt.Printf("Unzipping %s... ", lib.Zip)
		if err := file.Unzip(lib.Zip, lib.Path); err != nil {
			print.Error(err)
			return err
		} else {
			print.Ok()
		}

		fmt.Printf("Seeking %s... ", lib.Executable)
		if _, err := os.Stat(lib.Executable); err != nil {
			print.Error(err)
			return err
		} else {
			print.Ok()
		}
	}

	return nil
}

func GetFilteredIpOrDomain(ipOrDomain string) string {
	ipOrDomain = strings.ToLower(ipOrDomain)

	if netu.IsValidIPv4(ipOrDomain) {
		for _, exp := range config.App.Exclude.Ips {
			if IsIpExcluded(ipOrDomain, exp) {
				return ""
			}
		}
	} else {
		for _, exp := range config.App.Exclude.Hosts {
			if IsDomainExcluded(ipOrDomain, exp) {
				return ""
			}
		}
	}

	whoisRes := whois.GetWhois(ipOrDomain)
	if whoisRes != (whois.Whois{}) {
		for _, exp := range config.App.Exclude.Orgs {
			if IsOrgExcluded(whoisRes.Org, exp) {
				return ""
			}
		}
	}

	return ipOrDomain
}

func IsIpExcluded(ipStr string, exp string) bool {
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

func IsDomainExcluded(host string, exp string) bool {
	re := regexp.MustCompile(`(?i)^` + strings.Replace(exp, "*", "(.*?)", -1) + "$")
	matches := re.FindAllString(host, -1)
	if len(matches) == 1 {
		return true
	}
	return false
}

func IsOrgExcluded(org string, exp string) bool {
	re := regexp.MustCompile(`(?i)^` + strings.Replace(exp, "*", "(.*?)", -1) + "$")
	matches := re.FindAllString(org, -1)
	if len(matches) == 1 {
		return true
	}
	return false
}
