package whois

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/config"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/file"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/netu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
)

// Timeout and URI templates for Whois external services
const (
	HttpTimeout  = 10
	CacheTimeout = 172800
)

// Whois structure
type Whois struct {
	Source  string
	IP      string
	Country string
	Org     string
}

// ip.nf response structure
type ipNfWhois struct {
	IP struct {
		IP          string  `json:"ip"`
		Asn         string  `json:"asn"`
		Netmask     int     `json:"netmask"`
		Hostname    string  `json:"hostname"`
		City        string  `json:"city"`
		PostCode    string  `json:"post_code"`
		Country     string  `json:"country"`
		CountryCode string  `json:"country_code"`
		Latitude    float32 `json:"latitude"`
		Longitude   float32 `json:"longitude"`
	} `json:"ip"`
}

// ipinfo response structure
type ipInfoWhois struct {
	Error struct {
		Title   string `json:"title"`
		Message string `json:"message"`
	} `json:"error"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Loc      string `json:"loc"`
	Org      string `json:"org"`
	Postal   string `json:"postal"`
}

type ipApiWhois struct {
	As          string  `json:"as"`
	City        string  `json:"city"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Isp         string  `json:"isp"`
	Lat         float32 `json:"lat"`
	Lon         float32 `json:"lon"`
	Org         string  `json:"org"`
	Query       string  `json:"query"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	Status      string  `json:"status"`
	Timezone    string  `json:"timezone"`
	Zip         string  `json:"zip"`
}

// GetWhois info of ip address or domain
func GetWhois(ipAddressOrDomain string) Whois {
	var result Whois

	resultFile := path.Join(pathu.Tmp, "whois.json")
	resultJson := make(map[string]Whois)

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
			if err = json.Unmarshal(raw, &resultJson); err != nil {
				return result
			}
			if result, found := resultJson[ipAddressOrDomain]; found {
				return result
			}
		}
	}

	result, _ = getOnline(ipAddressOrDomain)
	resultJson[ipAddressOrDomain] = result
	resultJsonMarsh, _ := json.Marshal(resultJson)
	os.WriteFile(resultFile, resultJsonMarsh, 0644)
	return result
}

func getOnline(ip string) (Whois, error) {
	var result Whois
	var err error

	timeout := HttpTimeout * time.Second
	httpClient := http.Client{
		Timeout: timeout,
	}

	if !netu.IsValidIPv4(ip) {
		testIp, err := getWhatisIpAddress(httpClient, ip)
		if err == nil {
			ip = testIp
		} else {
			testIp, err = getDnsQueryIpAddress(httpClient, ip)
			if err != nil {
				return result, err
			}
			ip = testIp
		}
	}

	result.IP = ip
	result, err = getIpNfWhois(httpClient, ip)
	if err == nil {
		return result, nil
	}

	result, err = getIpInfoWhois(httpClient, ip)
	if err == nil {
		return result, nil
	}

	result, err = getIpapiWhois(httpClient, ip)
	if err == nil {
		return result, nil
	}

	return result, err
}

func getWhatisIpAddress(httpClient http.Client, ip string) (string, error) {
	var ipAddress string

	apiUrl := config.Settings.Uris.Whatis + ip

	resp, err := httpClient.Get(apiUrl)
	if err != nil {
		return ipAddress, err
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return ipAddress, err
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		if name, _ := s.Attr("name"); strings.EqualFold(name, "LOOKUPADDRESS") {
			ipAddress, _ = s.Attr("value")
			return
		}
	})

	if len(ipAddress) == 0 {
		return ipAddress, errors.New("Cannot retrieve IP address (too many queries ?)")
	}

	return ipAddress, nil
}

func getDnsQueryIpAddress(httpClient http.Client, ip string) (string, error) {
	var ipAddress string

	apiUrl := config.Settings.Uris.Dnsquery + ip

	cookieJar, _ := cookiejar.New(nil)
	httpClient = http.Client{
		Jar: cookieJar,
	}

	resp, err := httpClient.Get(apiUrl)
	if err != nil {
		return ipAddress, err
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return ipAddress, err
	}

	re := regexp.MustCompile(`(?i)url: 'https://dnsquery.org/whois,request/([^"]+)',`)
	newUri := re.FindStringSubmatch(doc.Text())
	if len(newUri) < 2 || !strings.HasPrefix(newUri[1], ip) {
		return ipAddress, errors.New("Cannot find token to retrieve IP address")
	}

	apiUrl = "https://dnsquery.org/whois,request/" + newUri[1]

	resp, err = httpClient.Get(apiUrl)
	if err != nil {
		return ipAddress, err
	}

	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return ipAddress, err
	}

	re = regexp.MustCompile(`(?i)\sresolving\sto\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),`)
	matches := re.FindStringSubmatch(doc.Text())
	if len(matches) == 2 {
		ipAddress = matches[1]
	}

	if len(ipAddress) == 0 {
		return ipAddress, errors.New("Cannot retrieve IP address (too many queries ?)")
	}

	return ipAddress, nil
}

func getIpapiWhois(httpClient http.Client, ip string) (Whois, error) {
	apiUrl := config.Settings.Uris.Ipapi + ip

	var result Whois
	result.IP = ip
	result.Source = apiUrl

	resp, err := httpClient.Get(apiUrl)
	if err != nil {
		return result, err
	}

	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		return result, errors.New("Exceeded maximum number of API calls")
	}

	var ipApi ipApiWhois
	err = json.NewDecoder(resp.Body).Decode(&ipApi)
	if err != nil {
		return result, err
	}

	if ipApi.Status != "success" {
		err := errors.New("Failed to find location data")
		return result, err
	}

	result.Country = ipApi.Country
	result.Org = strings.Replace(ipApi.Org, ",", ".", -1)

	return result, nil
}

func getIpInfoWhois(httpClient http.Client, ip string) (Whois, error) {
	apiUrl := fmt.Sprintf(config.Settings.Uris.Ipinfo, ip)

	var result Whois
	result.IP = ip
	result.Source = apiUrl

	resp, err := httpClient.Get(apiUrl)
	if err != nil {
		return result, err
	}

	defer resp.Body.Close()

	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		return result, errors.New("Exceeded maximum number of API calls")
	}

	var ipInfo ipInfoWhois
	err = json.NewDecoder(resp.Body).Decode(&ipInfo)
	if err != nil {
		return result, err
	}

	if ipInfo.Error.Title != "" {
		err := errors.New(ipInfo.Error.Message)
		return result, err
	}

	result.Country = ipInfo.Country
	result.Org = strings.Replace(ipInfo.Org, ",", ".", -1)

	return result, nil
}

func getIpNfWhois(httpClient http.Client, ip string) (Whois, error) {
	apiUrl := fmt.Sprintf(config.Settings.Uris.Ipnf, ip)

	var result Whois
	result.IP = ip
	result.Source = apiUrl

	resp, err := httpClient.Get(apiUrl)
	if err != nil {
		return result, err
	}

	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)

	var ipNf ipNfWhois
	err = json.NewDecoder(resp.Body).Decode(&ipNf)
	if err != nil {
		return result, errors.New(strings.TrimSpace(buf.String()))
	}

	result.Country = ipNf.IP.Country
	result.Org = strings.Replace(ipNf.IP.Asn, ",", ".", -1)

	return result, nil
}
