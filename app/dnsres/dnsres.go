package dnsres

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/crazy-max/WindowsSpyBlocker/app/utils/config"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/file"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/netu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
)

// Timeout and URI templates for DNS resolutions external services
const (
	HttpTimeout  = 10
	CacheTimeout = 172800
)

type dataIp struct {
	ResponseCode  string `json:"response_code"`
	ResolutionsIp []struct {
		LastResolved string `json:"last_resolved"`
		Domain       string `json:"domain"`
	} `json:"resolutions"`
	Hashes     []string `json:"hashes"`
	References []string `json:"references"`
	Permalink  string   `json:"permalink"`
}

type dataDomain struct {
	ResponseCode      string `json:"response_code"`
	ResolutionsDomain []struct {
		LastResolved string `json:"last_resolved"`
		IPAddress    string `json:"ip_address"`
	} `json:"resolutions"`
	Hashes     []string `json:"hashes"`
	Emails     []string `json:"emails"`
	Subdomains []string `json:"subdomains"`
	References []string `json:"references"`
	Permalink  string   `json:"permalink"`
}

// GetDnsRes returns the DNS resolutions of an ip address or domain
func GetDnsRes(ipAddressOrDomain string) Resolutions {
	var result Resolutions

	resultFile := path.Join(pathu.Tmp, "resolutions.json")
	resultJson := make(map[string]Resolutions)

	if resultTmpInfo, err := os.Stat(resultFile); err == nil {
		resultTmpModified := time.Since(resultTmpInfo.ModTime()).Seconds()
		if resultTmpModified > CacheTimeout {
			fmt.Printf("Creating file %s... ", resultFile)
			if err := file.CreateFile(resultFile); err != nil {
				return result
			}
		} else {
			raw, err := os.ReadFile(resultFile)
			if err != nil {
				return result
			}
			err = json.Unmarshal(raw, &resultJson)
			if err != nil {
				return result
			}
			if result, found := resultJson[ipAddressOrDomain]; found {
				sort.Sort(result)
				return result
			}
		}
	}

	reportType := "domain"
	if netu.IsValidIPv4(ipAddressOrDomain) {
		reportType = "ip"
	}

	result, _ = getOnline(reportType, ipAddressOrDomain)
	resultJson[ipAddressOrDomain] = result
	resultJsonMarsh, _ := json.Marshal(resultJson)
	_ = os.WriteFile(resultFile, resultJsonMarsh, 0644)
	return result
}

func getOnline(reportType string, ipOrDomain string) (Resolutions, error) {
	var result Resolutions
	uri := fmt.Sprintf(config.Settings.Uris.Threatcrowd, reportType, reportType, ipOrDomain)

	timeout := HttpTimeout * time.Second
	httpClient := http.Client{
		Timeout: timeout,
	}
	resp, err := httpClient.Get(uri)
	if err != nil {
		return result, err
	}

	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		return result, errors.New("Exceeded maximum number of API calls")
	}

	if reportType == "ip" {
		var dataIp dataIp
		err = json.NewDecoder(resp.Body).Decode(&dataIp)
		if err != nil {
			return result, err
		}
		if dataIp.ResponseCode != "1" || len(dataIp.ResolutionsIp) == 0 {
			err := errors.New("No data available")
			return result, err
		}
		for _, resolve := range dataIp.ResolutionsIp {
			lastResolved, _ := time.Parse("2006-01-02", resolve.LastResolved)
			result = append(result, Resolution{
				Source:       uri,
				LastResolved: lastResolved,
				IpOrDomain:   strings.TrimSpace(strings.ReplaceAll(resolve.Domain, `"`, ``)),
			})
		}

		sort.Sort(result)
		return result, nil
	}

	var dataDomain dataDomain
	err = json.NewDecoder(resp.Body).Decode(&dataDomain)
	if err != nil {
		return result, err
	}
	if dataDomain.ResponseCode != "1" || len(dataDomain.ResolutionsDomain) == 0 {
		err := errors.New("No data available")
		return result, err
	}
	for _, resolve := range dataDomain.ResolutionsDomain {
		lastResolved, _ := time.Parse("2006-01-02", resolve.LastResolved)
		result = append(result, Resolution{
			Source:       uri,
			LastResolved: lastResolved,
			IpOrDomain:   resolve.IPAddress,
		})
	}

	sort.Sort(result)
	return result, nil
}
