package diff

import (
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/data"
)

func menuWin7(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		menu.CommandOption{
			Description: "All",
			Function:    allWin7,
		},
		menu.CommandOption{
			Description: "Proxifier",
			Function:    proxifierWin7,
		},
		menu.CommandOption{
			Description: "Sysmon",
			Function:    sysmonWin7,
		},
		menu.CommandOption{
			Description: "Wireshark",
			Function:    wiresharkWin7,
		},
	}

	menuOptions := menu.NewOptions("Diff for Windows 7", "'menu' for help [dev-diff-win7]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}

func allWin7(args ...string) error {
	all(data.OS_WIN7)
	return nil
}

func proxifierWin7(args ...string) error {
	prog(data.OS_WIN7, "proxifier")
	return nil
}

func sysmonWin7(args ...string) error {
	prog(data.OS_WIN7, "sysmon")
	return nil
}

func wiresharkWin7(args ...string) error {
	prog(data.OS_WIN7, "sysmon")
	return nil
}
