package dev

import (
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/diff"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/proxifier"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/sysmon"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/wireshark"
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
)

func Menu(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		menu.CommandOption{
			Description: "> Proxifier : Extract events from log file",
			Function:    proxifier.Menu,
		},
		menu.CommandOption{
			Description: "> Sysmon    : Install / uninstall Sysmon and extract events from EVTX file",
			Function:    sysmon.Menu,
		},
		menu.CommandOption{
			Description: "> Wireshark : Extract events from PCAPNG file filtered by IPv4 hosts",
			Function:    wireshark.Menu,
		},
		menu.CommandOption{
			Description: "> Diff      : Generates a diff log based on CSV data of Sysmon, Proxifier and Wireshark",
			Function:    diff.Menu,
		},
	}

	menuOptions := menu.NewOptions("Dev", "'menu' for help [dev]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}
