package dev

import (
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/diff"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/firewall"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/merge"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/proxifier"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/sysmon"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/wireshark"
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
)

// Menu of Dev
func Menu(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "> Proxifier : Extract events from log file",
			Function:    proxifier.Menu,
		},
		{
			Description: "> Sysmon    : Install / uninstall Sysmon and extract events from EVTX file",
			Function:    sysmon.Menu,
		},
		{
			Description: "> Wireshark : Extract events from PCAPNG file filtered by IPv4 hosts",
			Function:    wireshark.Menu,
		},
		{
			Description: "> Firewall  : Test Firewall IPs rules with multiple Whois and DNS Resolutions",
			Function:    firewall.Menu,
		},
		{
			Description: "> Diff      : Generates a diff log based on CSV data",
			Function:    diff.Menu,
		},
		{
			Description: "> Merge     : Merge firewall and hosts data to multi format (DNSCrypt, OpenWrt, etc...)",
			Function:    merge.Menu,
		},
	}

	menuOptions := menu.NewOptions("Dev", "'menu' for help [dev]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}
