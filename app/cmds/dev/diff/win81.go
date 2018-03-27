package diff

import (
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/data"
	"github.com/fatih/color"
)

func menuWin81(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "All",
			Color:       color.FgHiYellow,
			Function:    allWin81,
		},
		{
			Description: "Proxifier",
			Color:       color.FgHiYellow,
			Function:    proxifierWin81,
		},
		{
			Description: "Sysmon",
			Color:       color.FgHiYellow,
			Function:    sysmonWin81,
		},
		{
			Description: "Wireshark",
			Color:       color.FgHiYellow,
			Function:    wiresharkWin81,
		},
	}

	menuOptions := menu.NewOptions("Diff for Windows 8.1", "'menu' for help [dev-diff-win81]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}

func allWin81(args ...string) error {
	all(data.OS_WIN81)
	return nil
}

func proxifierWin81(args ...string) error {
	prog(data.OS_WIN81, "proxifier")
	return nil
}

func sysmonWin81(args ...string) error {
	prog(data.OS_WIN81, "sysmon")
	return nil
}

func wiresharkWin81(args ...string) error {
	prog(data.OS_WIN81, "wireshark")
	return nil
}
