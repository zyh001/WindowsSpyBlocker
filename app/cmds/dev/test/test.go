package test

import (
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/fatih/color"
)

// Menu of Firewall
func Menu(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "Test firewall IPs",
			Color:       color.FgHiYellow,
			Function:    testFirewallIps,
		},
		{
			Description: "Test domains lookup",
			Color:       color.FgHiYellow,
			Function:    testHostsLookup,
		},
	}

	menuOptions := menu.NewOptions("Test", "'menu' for help [dev-test]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}
