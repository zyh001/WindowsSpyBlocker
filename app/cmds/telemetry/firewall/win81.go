package firewall

import (
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/data"
)

func menuWin81(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "Add extra rules",
			Function:    addWin81Extra,
		},
		{
			Description: "Add spy rules",
			Function:    addWin81Spy,
		},
		{
			Description: "Add update rules",
			Function:    addWin81Update,
		},
	}

	menuOptions := menu.NewOptions("Firewall rules for Windows 8.1", "'menu' for help [telemetry-firewall-win81]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}

func addWin81Extra(args ...string) error {
	addRules(data.OS_WIN81, data.RULES_EXTRA)
	return nil
}

func addWin81Spy(args ...string) error {
	addRules(data.OS_WIN81, data.RULES_SPY)
	return nil
}

func addWin81Update(args ...string) error {
	addRules(data.OS_WIN81, data.RULES_UPDATE)
	return nil
}
