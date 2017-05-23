package firewall

import (
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/data"
)

func menuWin7(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "Add extra rules",
			Function:    addWin7Extra,
		},
		{
			Description: "Add spy rules",
			Function:    addWin7Spy,
		},
		{
			Description: "Add update rules",
			Function:    addWin7Update,
		},
		{
			Description: "Test IPs",
			Function:    testIpsWin7,
		},
	}

	menuOptions := menu.NewOptions("Firewall rules for Windows 7", "'menu' for help [telemetry-firewall-win7]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}

func addWin7Extra(args ...string) error {
	addRules(data.OS_WIN7, data.RULES_EXTRA)
	return nil
}

func addWin7Spy(args ...string) error {
	addRules(data.OS_WIN7, data.RULES_SPY)
	return nil
}

func addWin7Update(args ...string) error {
	addRules(data.OS_WIN7, data.RULES_UPDATE)
	return nil
}

func testIpsWin7(args ...string) error {
	testIps(data.OS_WIN7)
	return nil
}
