package wireshark

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crazy-max/WindowsSpyBlocker/app/dnsres"
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/app"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/cmd"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/config"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/netu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/stringsu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/timeu"
	"github.com/crazy-max/WindowsSpyBlocker/app/whois"
	"github.com/fatih/color"
)

var libWiresharkPortable config.Lib

// Menu of Wireshark
func Menu(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "Extract log",
			Function:    extractLog,
		},
	}

	menuOptions := menu.NewOptions("Wireshark", "'menu' for help [dev-wireshark]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}

func init() {
	libWiresharkPortable = config.Lib{
		Url:        config.Libs.WiresharkPortable.Url,
		Checksum:   config.Libs.WiresharkPortable.Checksum,
		Zip:        path.Join(pathu.Libs, "wiresharkPortable.zip"),
		Path:       path.Join(pathu.Libs, "wiresharkPortable"),
		Executable: path.Join(pathu.Libs, "wiresharkPortable", "App", "Wireshark", "tshark.exe"),
	}
}

func extractLog(args ...string) (err error) {
	fmt.Println()
	defer timeu.Track(time.Now())

	var events Events

	if err := app.DownloadLib(libWiresharkPortable); err != nil {
		return nil
	}

	fmt.Printf("Opening %s... ", config.App.Wireshark.PcapngPath)
	pcapngFile, err := os.Open(config.App.Wireshark.PcapngPath)
	if err != nil {
		print.Error(err)
		return nil
	}
	print.Ok()
	defer pcapngFile.Close()

	fmt.Print("Extracting events... ")
	cmdResult, err := cmd.Exec(cmd.Options{
		Command:    libWiresharkPortable.Executable,
		Args:       []string{"-r", config.App.Wireshark.PcapngPath, "-q", "-z", "ip_hosts,tree"},
		WorkingDir: libWiresharkPortable.Path,
	})
	if err != nil {
		print.Error(err)
		return nil
	}

	if cmdResult.ExitCode != 0 {
		if len(cmdResult.Stderr) > 0 {
			print.Error(fmt.Errorf("%d\n%s\n", cmdResult.ExitCode, cmdResult.Stderr))
		} else {
			print.Error(fmt.Errorf("%d\n", cmdResult.ExitCode))
		}
		return nil
	}

	if len(cmdResult.Stdout) == 0 {
		print.Error(fmt.Errorf("No data found in %s\n", config.App.Wireshark.PcapngPath))
		return nil
	}

	print.Ok()

	lineCount := 0
	excluded := [][]string{}

	fmt.Println("Analyzing events...")
	//ioutil.WriteFile("wireshark.txt", []byte(cmdResult.Stdout), 0644)
	lines := strings.Split(cmdResult.Stdout, "\n")
	for _, line := range lines {
		values := strings.Split(stringsu.RemoveExtraSpaces(line), " ")
		if len(values) != 6 {
			continue
		}

		lineCount++

		// Exclude IPv6
		if !netu.IsValidIPv4(values[0]) {
			excluded = append(excluded, values)
			continue
		}

		host := app.GetFilteredIpOrDomain(values[0])
		if host == "" {
			excluded = append(excluded, values)
			continue
		}

		count, _ := strconv.Atoi(values[1])

		fmt.Println("Found", host)
		//color.New(color.FgCyan).Println(host)
		events = append(events, Event{
			IP:     host,
			Count:  count,
			DnsRes: dnsres.GetDnsRes(host),
			Whois:  whois.GetWhois(host),
		})
	}

	fmt.Println()
	fmt.Print("Total lines: ")
	color.New(color.FgYellow).Printf("%d\n", lineCount)
	fmt.Print("Processed: ")
	color.New(color.FgGreen).Printf("%d", len(events))
	fmt.Print(" (")
	color.New(color.FgRed).Printf("%d", len(excluded))
	fmt.Print(" excluded)\n")

	if len(events) == 0 {
		fmt.Println("No event to process...")
		return nil
	}

	// Generate and write file
	_writeCsvEventsHostFile("wireshark-hosts-count.csv", events)

	return nil
}

func _writeCsvEventsHostFile(filename string, events Events) {
	csvFile, _ := os.Create(path.Join(pathu.Logs, filename))
	fmt.Printf("\nGenerating %s... ", strings.TrimLeft(csvFile.Name(), pathu.Current))
	csvFile.WriteString("HOST,COUNT,ORGANIZATION,COUNTRY,RESOLVED DATE,RESOLVED DOMAIN")
	sort.Sort(events)
	for _, event := range events {
		csvFile.WriteString(fmt.Sprintf("\n%s,%v", event.IP, event.Count))

		if event.Whois != (whois.Whois{}) {
			csvFile.WriteString(fmt.Sprintf(",%s,%s", event.Whois.Org, event.Whois.Country))
		} else {
			csvFile.WriteString(",,")
		}

		if len(event.DnsRes) > 0 {
			countRes := 0
			for _, res := range event.DnsRes {
				if countRes == 0 {
					csvFile.WriteString(fmt.Sprintf(",%s,%s", res.LastResolved.Format("2006-01-02"), res.IpOrDomain))
				} else {
					csvFile.WriteString(fmt.Sprintf("\n,,,,%s,%s", res.LastResolved.Format("2006-01-02"), res.IpOrDomain))
				}
				countRes += 1
			}
		} else {
			csvFile.WriteString(",,")
		}
	}
	print.Ok()

	fmt.Printf("Writing %s... ", strings.TrimLeft(csvFile.Name(), pathu.Current))
	csvFile.Sync()
	if err := csvFile.Sync(); err != nil {
		print.Error(err)
	} else {
		print.Ok()
	}
	csvFile.Close()
}
