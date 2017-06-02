package firewall

import (
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/crazy-max/WindowsSpyBlocker/app/dnsres"
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/data"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/netu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/timeu"
	"github.com/crazy-max/WindowsSpyBlocker/app/whois"
	"github.com/fatih/color"
)

// Menu of Firewall
func Menu(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "Test Windows 7 IPs",
			Function:    testIpsWin7,
		},
		{
			Description: "Test Windows 8.1 IPs",
			Function:    testIpsWin81,
		},
		{
			Description: "Test Windows 10 IPs",
			Function:    testIpsWin10,
		},
	}

	menuOptions := menu.NewOptions("Firewall", "'menu' for help [dev-firewall]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}

func testIpsWin7(args ...string) error {
	testIps(data.OS_WIN7)
	return nil
}

func testIpsWin81(args ...string) error {
	testIps(data.OS_WIN81)
	return nil
}

func testIpsWin10(args ...string) error {
	testIps(data.OS_WIN10)
	return nil
}

func testIps(system string) {
	defer timeu.Track(time.Now())

	testIpsByRule(system, data.RULES_EXTRA)
	testIpsByRule(system, data.RULES_SPY)
	testIpsByRule(system, data.RULES_UPDATE)
}

func testIpsByRule(system string, rule string) {
	fmt.Println()

	testCsv := path.Join(pathu.Logs, system, fmt.Sprintf("firewall-test-%s.csv", rule))

	fmt.Printf("Get IPs for %s %s... ", system, rule)
	fwIps, err := data.GetFirewallIpsByRule(system, rule)
	if err != nil {
		print.Error(err)
		return
	}
	print.Ok()

	testCsvFile, _ := os.Create(testCsv)
	testCsvFile.WriteString("IP,ORGANIZATION,COUNTRY,RESOLVED DATE,RESOLVED DOMAIN")
	for _, fwIp := range fwIps {
		//TODO: Manage ip range for testing
		if strings.Contains(fwIp.IP, "-") {
			continue
		} else if netu.IsValidIPv4(fwIp.IP) {
			fmt.Print("\nTesting ")
			color.New(color.FgMagenta).Printf("%s", fwIp.IP)
			fmt.Print("...\n")
			whoisResult := whois.GetWhois(fwIp.IP)
			if whoisResult != (whois.Whois{}) {
				fmt.Print("  Organisation: ")
				color.New(color.FgCyan).Printf("%s\n", whoisResult.Org)
				fmt.Print("  Country: ")
				color.New(color.FgCyan).Printf("%s\n", whoisResult.Country)
				testCsvFile.WriteString(fmt.Sprintf("\n%s,%s,%s", fwIp.IP, whoisResult.Org, whoisResult.Country))
			} else {
				continue
			}
			dnsresList := dnsres.GetDnsRes(fwIp.IP)
			if len(dnsresList) > 0 {
				countRes := 0
				fmt.Println("  Resolutions:")
				for _, res := range dnsresList {
					fmt.Printf("    %s - ", res.LastResolved.Format("2006-01-02"))
					color.New(color.FgCyan).Printf("%s\n", res.IpOrDomain)
					if countRes == 0 {
						testCsvFile.WriteString(fmt.Sprintf(",%s,%s", res.LastResolved.Format("2006-01-02"), res.IpOrDomain))
					} else {
						testCsvFile.WriteString(fmt.Sprintf("\n,,,%s,%s", res.LastResolved.Format("2006-01-02"), res.IpOrDomain))
					}
					countRes += 1
				}
			} else {
				testCsvFile.WriteString(",,")
			}
		}
	}

	testCsvFile.Sync()
	testCsvFile.Close()
	fmt.Println()
}
