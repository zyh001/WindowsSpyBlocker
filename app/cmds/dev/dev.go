package dev

import (
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/crazy-max/WindowsSpyBlocker/app/bindata"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/diff"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/firewall"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/merge"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/proxifier"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/sysmon"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/wireshark"
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
	"github.com/fatih/color"
)

// Menu of Dev
func Menu(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "> Proxifier  : Extract events from log file",
			Color:       color.FgYellow,
			Function:    proxifier.Menu,
		},
		{
			Description: "> Sysmon     : Install / uninstall Sysmon and extract events from EVTX file",
			Color:       color.FgYellow,
			Function:    sysmon.Menu,
		},
		{
			Description: "> Wireshark  : Extract events from PCAPNG file filtered by IPv4 hosts",
			Color:       color.FgYellow,
			Function:    wireshark.Menu,
		},
		{
			Description: "> Firewall   : Test Firewall IPs rules with multiple Whois and DNS Resolutions",
			Color:       color.FgYellow,
			Function:    firewall.Menu,
		},
		{
			Description: "> Diff       : Generates a diff log based on CSV data",
			Color:       color.FgYellow,
			Function:    diff.Menu,
		},
		{
			Description: "> Merge      : Merge firewall and hosts data to multi format (DNSCrypt, OpenWrt, etc...)",
			Color:       color.FgYellow,
			Function:    merge.Menu,
		},
		{
			Description: "Extract data : Extract embedded data in the current folder",
			Color:       color.FgHiYellow,
			Function:    extractData,
		},
	}

	menuOptions := menu.NewOptions("Dev", "'menu' for help [dev]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}

func extractData(args ...string) (err error) {
	fmt.Println()

	if _, err := os.Stat(pathu.Data); err == nil {
		dataBackupPath := path.Join(pathu.Current, fmt.Sprintf("%s.%s", "data", time.Now().Format("20060102150405")))
		fmt.Printf("Backing current data folder in %s... ", strings.TrimLeft(dataBackupPath, pathu.Current))
		if err := os.Rename(pathu.Data, dataBackupPath); err != nil {
			print.Error(err)
			return nil
		}
		print.Ok()
	}

	fmt.Printf("Extracting data in %s... ", pathu.Data)
	if err := bindata.RestoreAssets(pathu.Current, "data"); err != nil {
		print.Error(err)
	}
	print.Ok()

	return nil
}
