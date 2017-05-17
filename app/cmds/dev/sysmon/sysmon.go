package sysmon

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
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
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/file"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/netu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/timeu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/windows"
	"github.com/crazy-max/WindowsSpyBlocker/app/whois"
	"github.com/fatih/color"
)

var libSysmon config.Lib
var libLogparser config.Lib

// Sysmon menu
func Menu(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "Install",
			Function:    install,
		},
		{
			Description: "Uninstall",
			Function:    uninstall,
		},
		{
			Description: "Extract event log",
			Function:    extractEventLog,
		},
	}

	menuOptions := menu.NewOptions("Sysmon", "'menu' for help [dev-sysmon]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}

func init() {
	libSysmon = config.Lib{
		Url:        config.Libs.Sysmon.Url,
		Checksum:   config.Libs.Sysmon.Checksum,
		Zip:        path.Join(pathu.Libs, "sysmon.zip"),
		Path:       path.Join(pathu.Libs, "sysmon"),
		Executable: path.Join(pathu.Libs, "sysmon", "Sysmon.exe"),
	}

	libLogparser = config.Lib{
		Url:        config.Libs.Logparser.Url,
		Checksum:   config.Libs.Logparser.Checksum,
		Zip:        path.Join(pathu.Libs, "logparser.zip"),
		Path:       path.Join(pathu.Libs, "logparser"),
		Executable: path.Join(pathu.Libs, "logparser", "LogParser.exe"),
	}
}

func install(args ...string) (err error) {
	fmt.Println()

	if !windows.IsAdmin() {
		return nil
	}

	if err := app.DownloadLib(libSysmon); err != nil {
		return nil
	}

	fmt.Print("Installing Sysmon... ")

	cmdResult, err := cmd.Exec(cmd.Options{
		Command: libSysmon.Executable,
		Args:    []string{"-i", "-accepteula", "-h", "md5", "-n", "-l"},
	})
	if err != nil {
		print.Error(err)
		return nil
	}

	// Sysmon already installed not redir to stderr but stdout...
	if cmdResult.ExitCode == 1242 {
		print.ErrorStr(fmt.Sprintf("%d", cmdResult.ExitCode))
		if len(cmdResult.Stdout) > 0 {
			print.ErrorStr(fmt.Sprintf("%s\n", cmdResult.Stdout))
		} else {
			fmt.Print("\n")
		}
		return nil
	}

	if cmdResult.ExitCode != 0 {
		print.ErrorStr(fmt.Sprintf("%d", cmdResult.ExitCode))
		if len(cmdResult.Stderr) > 0 {
			print.ErrorStr(fmt.Sprintf("%s\n", cmdResult.Stderr))
		} else {
			fmt.Print("\n")
		}
		return nil
	}

	print.Ok()
	if len(cmdResult.Stdout) > 0 {
		fmt.Println(cmdResult.Stdout)
	}

	// Set log max size to 2GB
	// https://technet.microsoft.com/en-us/library/cc748849%28v=ws.11%29.aspx
	maxLogSize := "2147483648"
	fmt.Printf("Setting max log size to %s bytes... ", maxLogSize)
	cmdResult, err = cmd.Exec(cmd.Options{
		Command: "wevtutil.exe",
		Args:    []string{"sl", "Microsoft-Windows-Sysmon/Operational", "/ms:" + maxLogSize},
	})
	if err != nil {
		print.Error(err)
		return nil
	}

	if cmdResult.ExitCode != 0 {
		print.ErrorStr(fmt.Sprintf("%d", cmdResult.ExitCode))
		if len(cmdResult.Stderr) > 0 {
			print.ErrorStr(fmt.Sprintf("%s\n", cmdResult.Stderr))
		}
		return nil
	}

	print.Ok()
	return nil
}

func uninstall(args ...string) (err error) {
	fmt.Println()

	if !windows.IsAdmin() {
		return nil
	}

	if err := app.DownloadLib(libSysmon); err != nil {
		return nil
	}

	fmt.Print("Uninstalling Sysmon... ")
	cmdResult, err := cmd.Exec(cmd.Options{
		Command: libSysmon.Executable,
		Args:    []string{"-u", "-accepteula"},
	})
	if err != nil {
		print.Error(err)
		return nil
	}

	if cmdResult.ExitCode != 0 {
		print.Error(fmt.Errorf("%d\n", cmdResult.ExitCode))
		if len(cmdResult.Stderr) > 0 {
			print.Error(fmt.Errorf("%s\n", cmdResult.Stderr))
		}
		return nil
	}

	print.Ok()
	if len(cmdResult.Stdout) > 0 {
		fmt.Println(cmdResult.Stdout)
	}

	evtxPath := path.Join(os.Getenv("SystemRoot"), `system32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`)
	fmt.Printf("Removing %s... ", evtxPath)
	if err := file.RemoveFile(evtxPath); err != nil {
		print.Error(err)
		return nil
	} else {
		print.Ok()
	}

	return nil
}

func extractEventLog(args ...string) (err error) {
	fmt.Println()
	defer timeu.Track(time.Now())

	var events EventsSortDate
	var eventsUnique EventsSortDate
	var eventsHostsCount EventsSortHost

	if err := app.DownloadLib(libLogparser); err != nil {
		return nil
	}

	fmt.Printf("Seeking %s... ", config.App.Sysmon.EvtxPath)
	if _, err := os.Stat(config.App.Sysmon.EvtxPath); err != nil {
		print.Error(err)
		return nil
	} else {
		print.Ok()
	}

	fmt.Print("Extracting events with LogParser... ")
	var logParserQuery bytes.Buffer
	logParserQuery.WriteString("SELECT RecordNumber,TO_UTCTIME(TimeGenerated),EventID,SourceName,ComputerName,SID,Strings")
	logParserQuery.WriteString(fmt.Sprintf(" FROM '%s'", strings.Replace(config.App.Sysmon.EvtxPath, "/", "\\", -1)))
	logParserQuery.WriteString(" WHERE EventID = '3'")

	cmdResult, err := cmd.Exec(cmd.Options{
		Command:    libLogparser.Executable,
		Args:       []string{"-i:evt", "-o:csv", logParserQuery.String()},
		WorkingDir: libLogparser.Path,
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
		print.Error(fmt.Errorf("No data found in %s\n", config.App.Sysmon.EvtxPath))
		return nil
	}

	print.Ok()

	lineCount := 0
	excluded := [][]string{}

	fmt.Println("Analyzing events...")
	//ioutil.WriteFile("sysmon.txt", []byte(cmd.Stdout), 0644)
	reader := csv.NewReader(strings.NewReader(cmdResult.Stdout))
	reader.Comma = ','
	reader.FieldsPerRecord = -1

	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			print.Error(err)
			return err
		} else if len(line) != 7 || line[2] != "3" {
			continue
		}

		lineCount++
		values := strings.Split(line[6], "|")

		// Exclude IPv6
		if values[12] == "true" {
			excluded = append(excluded, line)
			continue
		}

		host := app.GetFilteredIpOrDomain(values[13])
		if host == "" {
			excluded = append(excluded, line)
			continue
		}
		if values[14] != "" {
			host = app.GetFilteredIpOrDomain(values[14])
			if host == "" {
				excluded = append(excluded, line)
				continue
			}
		}

		eventDate, _ := time.Parse("2006-01-02 15:04:05.000", values[0])
		eventPort, _ := strconv.Atoi(values[15])

		fmt.Println("Found", host)
		//color.New(color.FgCyan).Println(host)
		event := Event{
			Date:     eventDate,
			Process:  values[3],
			Protocol: values[5],
			Host:     host,
			Port:     eventPort,
			PortName: strings.TrimSpace(values[16]),
			Whois:    whois.GetWhois(host),
		}
		events = append(events, event)

		eventFound := false
		for i := range eventsHostsCount {
			if eventsHostsCount[i].Host == host {
				eventsHostsCount[i].Count++
				eventFound = true
				break
			}
		}
		if !eventFound {
			event.Count = 1
			eventsHostsCount = append(eventsHostsCount, event)
		}
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

	csvAllFile, _ := os.Create(path.Join(pathu.Logs, "sysmon-all.csv"))
	fmt.Printf("\nGenerating %s... ", strings.TrimLeft(csvAllFile.Name(), pathu.Current))
	csvAllFile.WriteString("DATE,EXE,PID,ACCOUNT,HOST,ORGANIZATION,COUNTRY")
	duplicates := make(map[string]string)
	sort.Sort(events)
	for _, event := range events {
		csvAllFile.WriteString(fmt.Sprintf("\n%s,%s,%s,%s,%v,%s", event.Date.Format("2006-01-02 15:04:05"), event.Process, event.Protocol, event.Host, event.Port, event.PortName))
		if event.Whois != (whois.Whois{}) {
			csvAllFile.WriteString(fmt.Sprintf(",%s,%s", event.Whois.Org, event.Whois.Country))
		} else {
			csvAllFile.WriteString(",,")
		}

		eventHash := sha1.New()
		eventHash.Write([]byte(event.Process + event.Protocol + event.Host + event.PortName))
		eventHashStr := base64.URLEncoding.EncodeToString(eventHash.Sum(nil))
		if _, ok := duplicates[eventHashStr]; ok {
			continue
		} else {
			duplicates[eventHashStr] = event.Process + event.Protocol + event.Host + event.PortName
		}

		eventsUnique = append(eventsUnique, event)
	}
	print.Ok()

	fmt.Printf("Writing %s... ", strings.TrimLeft(csvAllFile.Name(), pathu.Current))
	if err := csvAllFile.Sync(); err != nil {
		print.Error(err)
	} else {
		print.Ok()
	}
	csvAllFile.Close()

	csvUniqueFile, _ := os.Create(path.Join(pathu.Logs, "sysmon-unique.csv"))
	fmt.Printf("Generating %s... ", strings.TrimLeft(csvUniqueFile.Name(), pathu.Current))
	csvUniqueFile.WriteString("DATE,EXE,PID,ACCOUNT,HOST,ORGANIZATION,COUNTRY")
	sort.Sort(eventsUnique)
	for _, event := range eventsUnique {
		csvUniqueFile.WriteString(fmt.Sprintf("\n%s,%s,%s,%s,%v,%s", event.Date.Format("2006-01-02 15:04:05"), event.Process, event.Protocol, event.Host, event.Port, event.PortName))
		if event.Whois != (whois.Whois{}) {
			csvUniqueFile.WriteString(fmt.Sprintf(",%s,%s", event.Whois.Org, event.Whois.Country))
		} else {
			csvUniqueFile.WriteString(",,")
		}
	}
	print.Ok()

	fmt.Printf("Writing %s... ", strings.TrimLeft(csvUniqueFile.Name(), pathu.Current))
	csvUniqueFile.Sync()
	if err := csvUniqueFile.Sync(); err != nil {
		print.Error(err)
	} else {
		print.Ok()
	}
	csvUniqueFile.Close()

	csvHostsCountFile, _ := os.Create(path.Join(pathu.Logs, "sysmon-hosts-count.csv"))
	fmt.Printf("Generating %s... ", strings.TrimLeft(csvHostsCountFile.Name(), pathu.Current))
	csvHostsCountFile.WriteString("HOST,COUNT,ORGANIZATION,COUNTRY,RESOLVED DATE,RESOLVED DOMAIN")
	sort.Sort(eventsHostsCount)
	for _, event := range eventsHostsCount {
		csvHostsCountFile.WriteString(fmt.Sprintf("\n%s,%v", event.Host, event.Count))

		if event.Whois != (whois.Whois{}) {
			csvHostsCountFile.WriteString(fmt.Sprintf(",%s,%s", event.Whois.Org, event.Whois.Country))
		} else {
			csvHostsCountFile.WriteString(",,")
		}

		dnsresList := dnsres.Resolutions{}
		if netu.IsValidIPv4(event.Host) {
			dnsresList = dnsres.GetDnsRes(event.Host)
		}
		if dnsresList.Len() > 0 {
			countRes := 0
			for _, res := range dnsresList {
				if countRes == 0 {
					csvHostsCountFile.WriteString(fmt.Sprintf(",%s,%s", res.LastResolved.Format("2006-01-02"), res.IpOrDomain))
				} else {
					csvHostsCountFile.WriteString(fmt.Sprintf("\n,,,,%s,%s", res.LastResolved.Format("2006-01-02"), res.IpOrDomain))
				}
				countRes += 1
			}
		} else {
			csvHostsCountFile.WriteString(",,")
		}
	}
	print.Ok()

	fmt.Printf("Writing %s... ", strings.TrimLeft(csvHostsCountFile.Name(), pathu.Current))
	csvHostsCountFile.Sync()
	if err := csvHostsCountFile.Sync(); err != nil {
		print.Error(err)
	} else {
		print.Ok()
	}
	csvHostsCountFile.Close()

	return nil
}
