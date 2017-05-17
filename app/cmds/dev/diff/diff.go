package diff

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/crazy-max/WindowsSpyBlocker/app/dnsres"
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/data"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/netu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/stringsu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/timeu"
	"github.com/crazy-max/WindowsSpyBlocker/app/whois"
	"github.com/fatih/color"
)

type diff struct {
	Host string `json:"host"`
}

type diffs []diff

func (slice diffs) Len() int {
	return len(slice)
}

func (slice diffs) Less(i, j int) bool {
	hostA := []byte(slice[i].Host)
	if netu.IsValidIPv4(slice[i].Host) {
		hostA = net.ParseIP(slice[i].Host)
	}
	hostB := []byte(slice[j].Host)
	if netu.IsValidIPv4(slice[j].Host) {
		hostB = net.ParseIP(slice[j].Host)
	}
	switch bytes.Compare(hostA, hostB) {
	case -1:
		return true
	case 0, 1:
		return false
	default:
		return false
	}
}

func (slice diffs) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

// Menu of Diff
func Menu(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "Windows 7",
			Function:    menuWin7,
		},
		{
			Description: "Windows 8.1",
			Function:    menuWin81,
		},
		{
			Description: "Windows 10",
			Function:    menuWin10,
		},
	}

	menuOptions := menu.NewOptions("Diff", "'menu' for help [dev-diff]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}

func all(system string) {
	fmt.Println()
	defer timeu.Track(time.Now())

	var resultsTmp diffs
	resultsTmp = append(resultsTmp, _diff(system, "proxifier", true)...)
	resultsTmp = append(resultsTmp, _diff(system, "sysmon", true)...)
	resultsTmp = append(resultsTmp, _diff(system, "wireshark", true)...)

	var results diffs
	duplicates := make(map[string]string)
	for _, resultTmp := range resultsTmp {
		if _, ok := duplicates[resultTmp.Host]; ok {
			continue
		}
		duplicates[resultTmp.Host] = resultTmp.Host
		results = append(results, resultTmp)
	}

	if len(results) == 0 {
		fmt.Println("No diffs found...")
		return
	}

	fmt.Println()
	color.New(color.FgGreen).Printf("%d", len(results))
	fmt.Print(" diff(s) found\n")

	_writeResultFile(system, "diff-all", results)
}

func prog(system string, prog string) {
	fmt.Println()
	defer timeu.Track(time.Now())

	_diff(system, prog, false)
}

func _diff(system string, prog string, all bool) diffs {
	var result diffs
	hostsCountPath := path.Join(pathu.Logs, system, prog+"-hosts-count.csv")

	fmt.Printf("Seeking %s... ", strings.TrimLeft(hostsCountPath, pathu.Current))
	if _, err := os.Stat(hostsCountPath); err != nil {
		print.Error(err)
		return result
	}
	print.Ok()

	fmt.Printf("Opening %s... ", strings.TrimLeft(hostsCountPath, pathu.Current))
	logFile, err := os.Open(hostsCountPath)
	if err != nil {
		print.Error(err)
		return result
	}
	print.Ok()
	defer logFile.Close()

	fmt.Print("Getting current data... ")
	dataList, err := _getCurrentData(system)
	if err != nil {
		print.Error(err)
		return result
	}
	print.Ok()

	fmt.Print("Comparing with current data... ")
	reader := csv.NewReader(logFile)
	reader.Comma = ','
	reader.FieldsPerRecord = -1

	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			print.Error(err)
			return result
		}

		host := strings.TrimSpace(line[0])
		if host == "" || host == "HOST" {
			continue
		}

		if !stringsu.InSlice(host, dataList) {
			result = append(result, diff{Host: host})
		}
	}
	print.Ok()

	if all {
		return result
	}

	if len(result) == 0 {
		fmt.Println("No diffs found...")
		return result
	}

	fmt.Println()
	color.New(color.FgGreen).Printf("%d", len(result))
	fmt.Print(" diff(s) found in ")
	color.New(color.FgYellow).Printf("%s\n", strings.TrimLeft(hostsCountPath, pathu.Current))

	_writeResultFile(system, "diff-"+prog, result)
	return nil
}

func _writeResultFile(system string, filename string, results diffs) {
	csvResultFile, _ := os.Create(path.Join(pathu.Logs, system, filename+".csv"))
	fmt.Printf("\nGenerating %s... ", strings.TrimLeft(csvResultFile.Name(), pathu.Current))
	csvResultFile.WriteString("HOST,ORGANIZATION,COUNTRY,RESOLVED DATE,RESOLVED DOMAIN")
	sort.Sort(results)
	for _, result := range results {
		csvResultFile.WriteString(fmt.Sprintf("\n%s", result.Host))
		whoisResult := whois.GetWhois(result.Host)
		if whoisResult != (whois.Whois{}) {
			csvResultFile.WriteString(fmt.Sprintf(",%s,%s", whoisResult.Org, whoisResult.Country))
		} else {
			csvResultFile.WriteString(",,")
		}
		if netu.IsValidIPv4(result.Host) {
			dnsresList := dnsres.GetDnsRes(result.Host)
			if len(dnsresList) > 0 {
				countRes := 0
				for _, res := range dnsresList {
					if countRes == 0 {
						csvResultFile.WriteString(fmt.Sprintf(",%s,%s", res.LastResolved.Format("2006-01-02"), res.IpOrDomain))
					} else {
						csvResultFile.WriteString(fmt.Sprintf("\n,,,%s,%s", res.LastResolved.Format("2006-01-02"), res.IpOrDomain))
					}
					countRes++
				}
			} else {
				csvResultFile.WriteString(",,")
			}
		}
	}
	print.Ok()

	fmt.Printf("Writing %s... ", strings.TrimLeft(csvResultFile.Name(), pathu.Current))
	if err := csvResultFile.Sync(); err != nil {
		print.Error(err)
	} else {
		print.Ok()
	}
	csvResultFile.Close()
}

func _getCurrentData(system string) ([]string, error) {
	var result []string

	firewallIPs, err := data.GetFirewallIps(system)
	if err != nil {
		return result, err
	}
	for _, firewallIP := range firewallIPs {
		if strings.Contains(firewallIP.IP, "-") {
			ips, err := netu.GetIpsFromIPRange(firewallIP.IP)
			if err != nil {
				return result, err
			}
			result = append(result, ips...)
		} else {
			result = append(result, firewallIP.IP)
		}
	}

	hosts, err := data.GetHosts(system)
	if err != nil {
		return result, err
	}
	for _, host := range hosts {
		result = append(result, host.Domain)
	}

	return result, nil
}
