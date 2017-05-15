package windows

import (
	"fmt"
	"os"

	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
	"github.com/fatih/color"
	"golang.org/x/sys/windows/registry"
)

func IsAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		color.New(color.FgYellow).Print("You need admin rights to execute this task...\n\n")
		return false
	}
	return true
}

func OpenRegKey(key registry.Key, path string, access uint32) (registry.Key, error) {
	fmt.Print("Opening key ")
	color.New(color.FgYellow).Printf("%s", path)
	fmt.Print("...")

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, access)
	if err != nil {
		print.Error(err)
		return key, err
	}

	print.Ok()
	return key, nil
}

func GetRegString(key registry.Key, name string) string {
	fmt.Print("Getting reg value of ")
	color.New(color.FgYellow).Printf("%s", name)
	fmt.Print("...")

	value, _, err := key.GetStringValue(name)
	if err != nil {
		print.Error(err)
		return ""
	}

	print.Ok()
	return value
}

func SetRegString(key registry.Key, name string, value string) error {
	fmt.Print("Setting ")
	color.New(color.FgYellow).Printf("%s", name)
	fmt.Print(" to ")
	color.New(color.FgCyan).Printf("'%s'", value)
	fmt.Print("...")

	if err := key.SetStringValue(name, value); err != nil {
		print.Error(err)
		return err
	}

	print.Ok()
	return nil
}
