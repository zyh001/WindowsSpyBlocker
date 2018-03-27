package diff

import (
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/data"
	"github.com/fatih/color"
)

func menuWin10(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "All",
			Color:       color.FgHiYellow,
			Function:    allWin10,
		},
		{
			Description: "Proxifier",
			Color:       color.FgHiYellow,
			Function:    proxifierWin10,
		},
		{
			Description: "Sysmon",
			Color:       color.FgHiYellow,
			Function:    sysmonWin10,
		},
		{
			Description: "Wireshark",
			Color:       color.FgHiYellow,
			Function:    wiresharkWin10,
		},
	}

	menuOptions := menu.NewOptions("Diff for Windows 10", "'menu' for help [dev-diff-win10]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}

func allWin10(args ...string) error {
	all(data.OS_WIN10)
	return nil
}

func proxifierWin10(args ...string) error {
	prog(data.OS_WIN10, "proxifier")
	return nil
}

func sysmonWin10(args ...string) error {
	prog(data.OS_WIN10, "sysmon")
	return nil
}

func wiresharkWin10(args ...string) error {
	prog(data.OS_WIN10, "wireshark")
	return nil
}
