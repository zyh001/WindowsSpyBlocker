package ip6

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/crazy-max/WindowsSpyBlocker/app/utils/config"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/file"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
)

// Timeout and URI templates for IP6 external services
const (
	HTTP_TIMEOUT  = 10
	CACHE_TIMEOUT = 172800
)

// IP6 structure
type IP6 struct {
	Domain string
	IP     string
}

// ip6.nf response structure
type ip6nl struct {
	Verdict      string `json:"verdict"`
	Cname        int    `json:"cname"`
	Domain       string `json:"domain"`
	Expires      int    `json:"expires"`
	Possiblyglue int    `json:"possiblyglue"`
	Rating       int    `json:"rating"`
	Time         int    `json:"time"`
	Results      struct {
		DNS struct {
			Class string   `json:"class"`
			V4    []string `json:"v4"`
			V6    []string `json:"v6"`
		} `json:"dns"`
		Host struct {
			Class string   `json:"class"`
			V4    []string `json:"v4"`
			V6    []string `json:"v6"`
		} `json:"host"`
		Mx struct {
			Class    string   `json:"class"`
			Comments []string `json:"comments"`
			V4       []string `json:"v4"`
			V6       []string `json:"v6"`
		} `json:"mx"`
		Ns struct {
			Class    string   `json:"class"`
			Comments []string `json:"comments"`
			V4       []string `json:"v4"`
			V6       []string `json:"v6"`
		} `json:"ns"`
		Www struct {
			Class    string   `json:"class"`
			Comments []string `json:"comments"`
			V4       []string `json:"v4"`
			V6       []string `json:"v6"`
		} `json:"www"`
	} `json:"results"`
}

// GetIP6 returns ipv6 of domain
func GetIP6(domain string) IP6 {
	var result IP6

	resultFile := path.Join(pathu.Tmp, "ip6.json")
	resultJson := make(map[string]IP6)

	if resultTmpInfo, err := os.Stat(resultFile); err == nil {
		resultTmpModified := time.Since(resultTmpInfo.ModTime()).Seconds()
		if resultTmpModified > CACHE_TIMEOUT {
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
			if result, found := resultJson[domain]; found {
				return result
			}
		}
	}

	result, _ = getOnline(domain)

	resultJson[domain] = result
	resultJsonMarsh, _ := json.Marshal(resultJson)
	os.WriteFile(resultFile, resultJsonMarsh, 0644)

	return result
}

func getOnline(domain string) (IP6, error) {
	var result IP6
	var err error

	timeout := time.Duration(HTTP_TIMEOUT * time.Second)
	httpClient := http.Client{
		Timeout: timeout,
	}

	result, err = getIP6(httpClient, domain)
	if err == nil {
		return result, nil
	}

	return result, err
}

func getIP6(httpClient http.Client, domain string) (IP6, error) {
	apiUrl := fmt.Sprintf(config.Settings.Uris.Ip6, domain)
	fmt.Printf("\n%s", apiUrl)

	resp, err := httpClient.Get(apiUrl)
	if err != nil {
		return IP6{}, err
	}

	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		return IP6{}, errors.New("Exceeded maximum number of API calls")
	}

	var ip6nlApi ip6nl
	err = json.NewDecoder(resp.Body).Decode(&ip6nlApi)
	if err != nil {
		return IP6{}, err
	}

	fmt.Printf("\n%v", ip6nlApi)
	for _, ipv6 := range ip6nlApi.Results.Host.V6 {
		return IP6{
			Domain: domain,
			IP:     ipv6,
		}, nil
	}

	return IP6{}, nil
}
