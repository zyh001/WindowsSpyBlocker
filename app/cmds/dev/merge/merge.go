package merge

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"time"

	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/config"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/data"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/file"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/netu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/stringsu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/timeu"
	"github.com/fatih/color"
)

// Menu of merge
func Menu(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "Windows 7",
			Function:    win7,
		},
		{
			Description: "Windows 8.1",
			Function:    win81,
		},
		{
			Description: "Windows 10",
			Function:    win10,
		},
	}

	menuOptions := menu.NewOptions("Merge", "'menu' for help [dev-merge]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}

func win7(args ...string) (err error) {
	_process(data.OS_WIN7)
	return nil
}

func win81(args ...string) (err error) {
	_process(data.OS_WIN81)
	return nil
}

func win10(args ...string) (err error) {
	_process(data.OS_WIN10)
	return nil
}

func _process(system string) {
	_procFirewall(system, data.RULES_EXTRA)
	_procFirewall(system, data.RULES_SPY)
	_procFirewall(system, data.RULES_UPDATE)
	_procHosts(system, data.RULES_EXTRA)
	_procHosts(system, data.RULES_SPY)
	_procHosts(system, data.RULES_UPDATE)
}

func _procFirewall(system string, rule string) {
	fmt.Println()
	color.New(color.FgHiYellow, color.Bold).Printf("Firewall %s %s", system, rule)
	fmt.Println()
	firewallDataPath := path.Join(pathu.Current, "data", data.TYPE_FIREWALL, system, rule+".txt")

	fmt.Printf("Seeking %s... ", strings.TrimLeft(firewallDataPath, pathu.Current))
	if _, err := os.Stat(firewallDataPath); err != nil {
		print.Error(err)
		return
	}
	print.Ok()

	fmt.Printf("Opening %s... ", strings.TrimLeft(firewallDataPath, pathu.Current))
	logFile, err := os.Open(firewallDataPath)
	if err != nil {
		print.Error(err)
		return
	}
	print.Ok()
	defer logFile.Close()

	fmt.Printf("Reading %s... ", strings.TrimLeft(firewallDataPath, pathu.Current))
	firewallDataBuf, err := ioutil.ReadFile(firewallDataPath)
	if err != nil {
		print.Error(err)
		return
	}
	print.Ok()
	//print.Pretty(strings.Split(string(firewallDataBuf), "\n"))

	err = _procExtIPs(system, rule, data.EXT_OPENWRT, firewallDataBuf)
	if err != nil {
		return
	}

	err = _procExtIPs(system, rule, data.EXT_PROXIFIER, firewallDataBuf)
	if err != nil {
		return
	}

	err = _procExtIPs(system, rule, data.EXT_SIMPLEWALL, firewallDataBuf)
	if err != nil {
		return
	}
}

func _procHosts(system string, rule string) {
	fmt.Println()
	color.New(color.FgHiYellow, color.Bold).Printf("Hosts %s %s", system, rule)
	fmt.Println()
	hostsDataPath := path.Join(pathu.Current, "data", data.TYPE_HOSTS, system, rule+".txt")

	fmt.Printf("Seeking %s... ", strings.TrimLeft(hostsDataPath, pathu.Current))
	if _, err := os.Stat(hostsDataPath); err != nil {
		print.Error(err)
		return
	}
	print.Ok()

	fmt.Printf("Opening %s... ", strings.TrimLeft(hostsDataPath, pathu.Current))
	logFile, err := os.Open(hostsDataPath)
	if err != nil {
		print.Error(err)
		return
	}
	print.Ok()
	defer logFile.Close()

	fmt.Printf("Reading %s... ", strings.TrimLeft(hostsDataPath, pathu.Current))
	hostsDataBuf, err := ioutil.ReadFile(hostsDataPath)
	if err != nil {
		print.Error(err)
		return
	}
	print.Ok()
	//print.Pretty(strings.Split(string(firewallDataBuf), "\n"))

	err = _procExtHosts(system, rule, data.EXT_DNSCRYPT, hostsDataBuf)
	if err != nil {
		return
	}

	err = _procExtHosts(system, rule, data.EXT_OPENWRT, hostsDataBuf)
	if err != nil {
		return
	}

	err = _procExtHosts(system, rule, data.EXT_PROXIFIER, hostsDataBuf)
	if err != nil {
		return
	}
}

func _procExtIPs(system string, rule string, ext string, firewallDataBuf []byte) error {
	asCidr := false
	outputPath := ""
	fileHead := ""
	fileIpValue := ""

	if ext == data.EXT_OPENWRT {
		asCidr = true
		outputPath = path.Join(pathu.Data, ext, system, rule, "firewall.user")
		fileHead = fmt.Sprintf(data.OPENWRT_IP_HEAD, system, rule, config.URL)
		fileIpValue = data.OPENWRT_IP_VALUE
	} else if ext == data.EXT_PROXIFIER {
		asCidr = false
		outputPath = path.Join(pathu.Data, ext, system, rule, "ips.txt")
		fileHead = data.PROXIFIER_IP_HEAD
		fileIpValue = data.PROXIFIER_IP_VALUE
	} else if ext == data.EXT_SIMPLEWALL {
		asCidr = false
		outputPath = path.Join(pathu.Data, ext, system, rule, "blocklist.xml")
		fileHead = fmt.Sprintf(data.SIMPLEWALL_HEAD, system, rule, config.URL, timeu.CurrentTime.Format(time.RFC1123Z))
		fileIpValue = data.SIMPLEWALL_VALUE
	}

	color.New(color.FgMagenta).Printf("\nProcessing %s\n", ext)

	fmt.Printf("Getting %s data... ", ext)
	extData, err := data.GetExtIPs(ext, system, rule)
	if err != nil {
		print.Error(err)
		return err
	}
	print.Ok()

	fmt.Printf("Seeking diffs for %s... ", ext)
	result, added, removed, err := _getDiffsIPs(data.GetIPsSlice(extData), firewallDataBuf, asCidr)
	if err != nil {
		print.Error(err)
		return err
	} else if len(added) == 0 && len(removed) == 0 {
		color.New(color.FgYellow).Print("0 diff found\n")
	} else {
		if len(added) > 0 {
			color.New(color.FgGreen).Printf("%d added", len(added))
		}
		if len(added) > 0 && len(removed) > 0 {
			fmt.Print(" ; ")
		}
		if len(removed) > 0 {
			color.New(color.FgRed).Printf("%d removed", len(removed))
		}
		fmt.Print("\n")
	}

	if _, err := os.Stat(path.Dir(outputPath)); os.IsNotExist(err) {
		fmt.Printf("Creating folder %s... ", strings.TrimLeft(path.Dir(outputPath), pathu.Current))
		if err := file.CreateSubfolder(path.Dir(outputPath)); err != nil {
			print.Error(err)
			return err
		}
		print.Ok()
	}

	fmt.Printf("Generating %s... ", strings.TrimLeft(outputPath, pathu.Current))
	outputFile, _ := os.Create(outputPath)
	outputFile.WriteString(fileHead)
	count := 0
	for _, ip := range result {
		if count > 0 {
			outputFile.WriteString("\n")
		}
		if ext == data.EXT_SIMPLEWALL {
			outputFile.WriteString(fmt.Sprintf(fileIpValue, system, rule, ip.IP, ip.IP))
		} else {
			outputFile.WriteString(fmt.Sprintf(fileIpValue, ip.IP))
		}
		count++
	}
	if ext == data.EXT_SIMPLEWALL {
		outputFile.WriteString("\n</root>")
	}
	print.Ok()

	fmt.Printf("Writing %s... ", strings.TrimLeft(outputPath, pathu.Current))
	if err := outputFile.Sync(); err != nil {
		print.Error(err)
	} else {
		print.Ok()
	}
	outputFile.Close()

	return nil
}

func _procExtHosts(system string, rule string, ext string, hostsDataBuf []byte) error {
	outputPath := ""
	fileHead := ""
	fileValue := ""
	asWildcard := false
	if ext == data.EXT_DNSCRYPT {
		outputPath = path.Join(pathu.Data, ext, system, rule+".txt")
		fileHead = data.DNSCRYPT_HEAD
		fileValue = data.DNSCRYPT_VALUE
		asWildcard = true
	} else if ext == data.EXT_OPENWRT {
		outputPath = path.Join(pathu.Data, ext, system, rule, "dnsmasq.conf")
		fileHead = fmt.Sprintf(data.OPENWRT_DOMAINS_HEAD, system, rule, config.URL)
		fileValue = data.OPENWRT_DOMAINS_VALUE
		asWildcard = false
	} else if ext == data.EXT_PROXIFIER {
		outputPath = path.Join(pathu.Data, ext, system, rule, "domains.txt")
		fileHead = data.PROXIFIER_DOMAINS_HEAD
		fileValue = data.PROXIFIER_DOMAINS_VALUE
		asWildcard = true
	}

	color.New(color.FgMagenta).Printf("\nProcessing %s\n", ext)

	fmt.Printf("Getting %s data... ", ext)
	extData, err := data.GetExtHosts(ext, system, rule)
	if err != nil {
		print.Error(err)
		return err
	}
	print.Ok()

	fmt.Printf("Seeking diffs for %s... ", ext)
	result, added, removed, err := _getDiffsHosts(data.GetHostsSlice(extData), hostsDataBuf, asWildcard)
	if err != nil {
		print.Error(err)
		return err
	} else if len(added) == 0 && len(removed) == 0 {
		color.New(color.FgYellow).Print("0 diff found\n")
	} else {
		if len(added) > 0 {
			color.New(color.FgGreen).Printf("%d added", len(added))
		}
		if len(added) > 0 && len(removed) > 0 {
			fmt.Print(" ; ")
		}
		if len(removed) > 0 {
			color.New(color.FgRed).Printf("%d removed", len(removed))
		}
		fmt.Print("\n")
	}

	if _, err := os.Stat(path.Dir(outputPath)); os.IsNotExist(err) {
		fmt.Printf("Creating folder %s... ", strings.TrimLeft(path.Dir(outputPath), pathu.Current))
		if err := file.CreateSubfolder(path.Dir(outputPath)); err != nil {
			print.Error(err)
			return err
		}
		print.Ok()
	}

	fmt.Printf("Generating %s... ", strings.TrimLeft(outputPath, pathu.Current))
	outputFile, _ := os.Create(outputPath)
	outputFile.WriteString(fileHead)
	count := 0
	for _, domain := range result {
		if count > 0 {
			outputFile.WriteString("\n")
		}
		outputFile.WriteString(fmt.Sprintf(fileValue, domain.Domain))
		count++
	}
	print.Ok()

	fmt.Printf("Writing %s... ", strings.TrimLeft(outputPath, pathu.Current))
	if err := outputFile.Sync(); err != nil {
		print.Error(err)
	} else {
		print.Ok()
	}
	outputFile.Close()

	return nil
}

func _getDiffsIPs(extIps []string, firewallIPsBuf []byte, asCidr bool) (ips, []string, []string, error) {
	var result ips
	var added []string
	var removed []string
	var err error

	var firewallIP string
	var firewallIPs []string

	newBuf := bytes.NewBuffer(firewallIPsBuf)
	for {
		firewallIP, err = newBuf.ReadString('\n')
		if len(firewallIP) == 0 {
			if err != nil {
				if err == io.EOF {
					break
				}
				return result, nil, nil, err
			}
		}
		firewallIP = strings.TrimSpace(firewallIP)
		if strings.HasPrefix(firewallIP, "#") || firewallIP == "" {
			continue
		}
		firewallIPs = append(firewallIPs, firewallIP)
		if asCidr && strings.Contains(firewallIP, "-") {
			firewallIP, err = netu.GetCIDRFromIPRange(firewallIP)
			if err != nil {
				return result, nil, nil, err
			}
		} else if !asCidr && strings.Contains(firewallIP, "/") {
			firewallIP, err = netu.GetIPRangeFromCIDR(firewallIP)
			if err != nil {
				return result, nil, nil, err
			}
		}
		if !stringsu.InSlice(firewallIP, extIps) {
			added = append(added, firewallIP)
		}
		result = append(result, ip{IP: firewallIP})
	}

	for _, extIp := range extIps {
		if strings.Contains(extIp, "/") {
			extIp, err = netu.GetIPRangeFromCIDR(extIp)
			if err != nil {
				return result, nil, nil, err
			}
		}
		if !stringsu.InSlice(extIp, firewallIPs) {
			removed = append(removed, extIp)
		}
	}

	sort.Sort(result)
	return result, added, removed, nil
}

func _getDiffsHosts(extHosts []string, hostsBuf []byte, asWildcard bool) (hosts, []string, []string, error) {
	var result hosts
	var added []string
	var removed []string
	var err error

	var domain string
	var domains []string

	newBuf := bytes.NewBuffer(hostsBuf)
	for {
		domain, err = newBuf.ReadString('\n')
		if len(domain) == 0 {
			if err != nil {
				if err == io.EOF {
					break
				}
				return result, nil, nil, err
			}
		}
		domain = strings.TrimRight(strings.TrimLeft(strings.TrimSpace(domain), "0.0.0.0 "), ":443")
		if strings.HasPrefix(domain, "#") || domain == "" {
			continue
		}
		if asWildcard {
			for _, wildcard := range data.WilcardSubdomains {
				exp := strings.Replace(strings.Replace(wildcard, "*", `([^"]+)`, -1), ".", `\.`, -1)
				re := regexp.MustCompile(`(?i)` + exp)
				if re.MatchString(domain) {
					domain = wildcard
					break
				}
			}
		}
		if !stringsu.InSlice(domain, domains) {
			domains = append(domains, domain)
		} else {
			continue
		}
		if !stringsu.InSlice(domain, extHosts) {
			added = append(added, domain)
		}
		result = append(result, host{Domain: domain})
	}

	for _, extHost := range extHosts {
		if !stringsu.InSlice(extHost, domains) {
			removed = append(removed, extHost)
		}
	}

	sort.Sort(result)
	return result, added, removed, nil
}
