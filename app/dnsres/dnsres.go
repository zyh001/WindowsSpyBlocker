package dnsres

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"sort"
	"time"

	"github.com/crazy-max/WindowsSpyBlocker/app/utils/file"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/netu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
	"github.com/fatih/color"
)

// Timeout and URI templates for DNS resolutions external services
const (
	HTTP_TIMEOUT  = 10
	CACHE_TIMEOUT = 172800

	THREATCROWD_URI = "https://www.threatcrowd.org/searchApi/v2/%s/report/?%s=%s"
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

// Get DNS resolutions of ip address or domain
func GetDnsRes(ipAddressOrDomain string) Resolutions {
	return getDnsRes(ipAddressOrDomain, false)
}

func getDnsRes(ipAddressOrDomain string, printed bool) Resolutions {
	var result Resolutions

	if printed {
		fmt.Print("Get resolutions of ")
		color.New(color.FgYellow).Printf("%s", ipAddressOrDomain)
		fmt.Print(" from ")
	}

	resultFile := path.Join(pathu.Tmp, "resolutions.json")
	resultJson := make(map[string]Resolutions)

	if resultTmpInfo, err := os.Stat(resultFile); err == nil {
		resultTmpModified := time.Since(resultTmpInfo.ModTime()).Seconds()
		if resultTmpModified > CACHE_TIMEOUT {
			if printed {
				fmt.Printf("Creating file %s... ", resultFile)
			}
			if err := file.CreateFile(resultFile); err != nil {
				if printed {
					print.Error(err)
				}
				return result
			}
		} else {
			raw, err := ioutil.ReadFile(resultFile)
			if err != nil {
				if printed {
					print.Error(err)
				}
				return result
			}
			err = json.Unmarshal(raw, &resultJson)
			if err != nil {
				if printed {
					print.Error(err)
				}
				return result
			}
			if result, found := resultJson[ipAddressOrDomain]; found {
				if printed {
					color.New(color.FgMagenta).Print("cache")
					fmt.Print("... ")
					print.Ok()
				}
				sort.Sort(result)
				return result
			}
		}
	}

	if printed {
		color.New(color.FgMagenta).Print("online api")
		fmt.Print("... ")
	}

	reportType := "domain"
	if netu.IsValidIPv4(ipAddressOrDomain) {
		reportType = "ip"
	}

	result, err := getOnline(reportType, ipAddressOrDomain)
	if err != nil {
		if printed {
			print.Error(err)
		}
	} else {
		if printed {
			print.Ok()
		}
	}

	resultJson[ipAddressOrDomain] = result
	resultJsonMarsh, err := json.Marshal(resultJson)
	if err != nil {
		if printed {
			print.Error(err)
		}
	}

	err = ioutil.WriteFile(resultFile, resultJsonMarsh, 0644)
	if err != nil {
		if printed {
			print.Error(err)
		}
	}

	return result
}

func getOnline(reportType string, ipOrDomain string) (Resolutions, error) {
	var result Resolutions
	uri := fmt.Sprintf(THREATCROWD_URI, reportType, reportType, ipOrDomain)

	timeout := time.Duration(HTTP_TIMEOUT * time.Second)
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
				IpOrDomain:   resolve.Domain,
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
