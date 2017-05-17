//go:generate go get -v github.com/jteeuwen/go-bindata/go-bindata/...
//go:generate go-bindata -pkg bindata -o app/bindata/bindata.go data/... app.conf
//go:generate go get -v github.com/josephspurrier/goversioninfo/...
//go:generate goversioninfo -icon=app.ico -manifest=app.manifest

package main

import (
	"fmt"
	"os/exec"

	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/firewall"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/ncsi"
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/config"
	"github.com/fatih/color"
)

func init() {
	// Set window title
	exec.Command("cmd", "/c", fmt.Sprintf("title %s %s", config.NAME, config.VERSION)).Run()
}

func main() {
	color.New(color.FgHiWhite).Println(config.NAME + " " + config.VERSION)
	color.New(color.FgHiWhite).Println(config.URL)

	menuCommands := []menu.CommandOption{
		{
			Description: "> Firewall  : Add or remove firewall rules and resolve IPs adresses",
			Function:    firewall.Menu,
		},
		{
			Description: "> NCSI      : Apply an alternate NCSI and test your internet connection the Microsoft way",
			Function:    ncsi.Menu,
		},
		{
			Description: "> Dev       : Several tools used by WindowsSpyBlocker",
			Function:    dev.Menu,
		},
	}

	menuOptions := menu.NewOptions("Main", "'menu' for help [main]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
}
