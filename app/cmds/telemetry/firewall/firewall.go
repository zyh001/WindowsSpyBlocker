package firewall

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/cmd"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/data"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/stringsu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/timeu"
	"github.com/fatih/color"
	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// PREFIX for firewall rule
const PREFIX = "windowsSpyBlocker"

// Menu of Firewall
func Menu(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "> Windows 7 firewall rules",
			Function:    menuWin7,
		},
		{
			Description: "> Windows 8.1 firewall rules",
			Function:    menuWin81,
		},
		{
			Description: "> Windows 10 firewall rules",
			Function:    menuWin10,
		},
		{
			Description: "Remove WindowsSpyBlocker rules",
			Function:    removeRules,
		},
		{
			Description: "Display your current WindowsSpyBlocker rules",
			Function:    currentRules,
		},
	}

	menuOptions := menu.NewOptions("Firewall", "'menu' for help [telemetry-firewall]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}

func addRules(system string, rule string) {
	fmt.Println()
	defer timeu.Track(time.Now())

	prefix := getPrefix(system, rule)
	fmt.Printf("Get IPs for %s %s... ", system, rule)
	ips, err := data.GetFirewallIpsByRule(system, rule)
	if err != nil {
		print.Error(err)
		return
	}
	print.Ok()

	for _, ip := range ips {
		addFirewallRule(prefix, ip.IP)
	}
}

func removeRules(args ...string) error {
	fmt.Println()
	defer timeu.Track(time.Now())

	system, rule := "", ""
	if len(args) > 0 {
		system = args[0]
		rule = args[1]
	}

	prefix := getPrefix(system, rule)
	fmt.Print("Remove rules starting with")
	color.New(color.FgYellow).Printf(" %s", prefix)
	fmt.Print("...\n")

	ole.CoInitialize(0)
	defer ole.CoUninitialize()

	unk, err := oleutil.CreateObject("HNetCfg.FwPolicy2")
	if err != nil {
		print.ErrorStr(fmt.Sprintf("Error creating HNetCfg.FwPolicy2 object: %s\n", err.Error()))
		return nil
	}

	dsp, err := unk.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		print.ErrorStr(fmt.Sprintf("Error querying IID_IDispatch interface: %s\n", err.Error()))
		return nil
	}

	rules := oleutil.MustGetProperty(dsp, "Rules").ToIDispatch()
	oleutil.ForEach(rules, func(v *ole.VARIANT) error {
		rule := v.ToIDispatch()
		name := oleutil.MustGetProperty(rule, "Name").ToString()
		if strings.HasPrefix(name, prefix) {
			removeFirewallRule(name)
		}
		return nil
	})

	return nil
}

func currentRules(args ...string) error {
	fmt.Println()

	ole.CoInitialize(0)
	defer ole.CoUninitialize()

	unk, err := oleutil.CreateObject("HNetCfg.FwPolicy2")
	if err != nil {
		print.ErrorStr(fmt.Sprintf("Error creating HNetCfg.FwPolicy2 object: %s\n", err.Error()))
		return nil
	}

	dsp, err := unk.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		print.ErrorStr(fmt.Sprintf("Error querying IID_IDispatch interface: %s\n", err.Error()))
		return nil
	}

	rules := oleutil.MustGetProperty(dsp, "Rules").ToIDispatch()
	oleutil.ForEach(rules, func(v *ole.VARIANT) error {
		rule := v.ToIDispatch()
		name := oleutil.MustGetProperty(rule, "Name").ToString()
		//remoteaddr := oleutil.MustGetProperty(rule, "RemoteAddresses").ToString()
		if strings.HasPrefix(name, getPrefix("", "")) {
			fmt.Println(name)
		}
		return nil
	})

	return nil
}

func getPrefix(system string, rule string) string {
	var prefix bytes.Buffer
	prefix.WriteString(PREFIX)
	if len(system) > 0 && len(rule) > 0 {
		prefix.WriteString(stringsu.UcFirst(system))
		prefix.WriteString(stringsu.UcFirst(rule))
	}
	return prefix.String()
}

func addFirewallRule(prefix string, ip string) {
	fmt.Print("Adding outbound firewall rule for")
	color.New(color.FgCyan).Printf(" %s", ip)
	fmt.Print("... ")

	ole.CoInitialize(0)
	defer ole.CoUninitialize()

	unk, err := oleutil.CreateObject("HNetCfg.FwPolicy2")
	if err != nil {
		print.ErrorStr(fmt.Sprintf("Error creating HNetCfg.FwPolicy2 object: %s\n", strings.TrimSpace(err.Error())))
		return
	}

	dsp, err := unk.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		print.ErrorStr(fmt.Sprintf("Error querying IID_IDispatch interface: %s\n", strings.TrimSpace(err.Error())))
		return
	}

	rules := oleutil.MustGetProperty(dsp, "Rules").ToIDispatch()
	err = oleutil.ForEach(rules, func(v *ole.VARIANT) error {
		rule := v.ToIDispatch()
		name := oleutil.MustGetProperty(rule, "Name").ToString()
		//remoteaddr := oleutil.MustGetProperty(rule, "RemoteAddresses").ToString()
		if name == fmt.Sprintf("%s-%s", prefix, ip) {
			return errors.New("emit macho dwarf: elf header corrupted")
		}
		return nil
	})
	if err != nil {
		color.New(color.FgYellow).Print("Warning: Rule already exists\n")
		return
	}

	cmdResult, err := cmd.Exec(cmd.Options{
		Command: "netsh",
		Args: []string{
			"advfirewall", "firewall", "add", "rule",
			fmt.Sprintf(`name="%s-%s"`, prefix, ip),
			"dir=out", "protocol=any", "action=block", fmt.Sprintf(`remoteip="%s"`, ip),
		},
	})
	if err != nil {
		print.Error(err)
		return
	}

	if cmdResult.ExitCode != 0 {
		if len(cmdResult.Stderr) > 0 {
			print.ErrorStr(fmt.Sprintf("%d\n%s\n", cmdResult.ExitCode, cmdResult.Stderr))
		} else if len(cmdResult.Stdout) > 0 {
			print.ErrorStr(fmt.Sprintf("%d\n%s\n", cmdResult.ExitCode, cmdResult.Stdout))
		} else {
			print.ErrorStr(fmt.Sprintf("%d\n", cmdResult.ExitCode))
		}
		return
	}

	print.Ok()
}

func removeFirewallRule(name string) {
	fmt.Print("Removing firewall rule")
	color.New(color.FgYellow).Printf(" %s", name)
	fmt.Print("... ")

	cmdResult, err := cmd.Exec(cmd.Options{
		Command: "netsh",
		Args: []string{
			"advfirewall", "firewall", "delete", "rule",
			fmt.Sprintf(`name="%s"`, name),
		},
	})
	if err != nil {
		print.Error(err)
		return
	}

	if cmdResult.ExitCode != 0 {
		if len(cmdResult.Stderr) > 0 {
			print.ErrorStr(fmt.Sprintf("%d\n%s\n", cmdResult.ExitCode, cmdResult.Stderr))
		} else if len(cmdResult.Stdout) > 0 {
			print.ErrorStr(fmt.Sprintf("%d\n%s\n", cmdResult.ExitCode, cmdResult.Stdout))
		} else {
			print.ErrorStr(fmt.Sprintf("%d\n", cmdResult.ExitCode))
		}
		return
	}

	print.Ok()
}
