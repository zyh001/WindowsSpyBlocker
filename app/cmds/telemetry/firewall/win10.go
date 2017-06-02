package firewall

import (
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/data"
)

func menuWin10(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "Add extra rules",
			Function:    addWin10Extra,
		},
		{
			Description: "Add spy rules",
			Function:    addWin10Spy,
		},
		{
			Description: "Add update rules",
			Function:    addWin10Update,
		},
	}

	menuOptions := menu.NewOptions("Firewall rules for Windows 10", "'menu' for help [telemetry-firewall-win10]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}

func addWin10Extra(args ...string) error {
	addRules(data.OS_WIN10, data.RULES_EXTRA)
	return nil
}

func addWin10Spy(args ...string) error {
	addRules(data.OS_WIN10, data.RULES_SPY)
	return nil
}

func addWin10Update(args ...string) error {
	addRules(data.OS_WIN10, data.RULES_UPDATE)
	return nil
}
