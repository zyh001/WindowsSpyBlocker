package print

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/fatih/color"
)

func Error(err error) {
	color.New(color.FgRed).Printf("Error: %s\n", err.Error())
}

func ErrorStr(str string) {
	color.New(color.FgRed).Printf("Error: %s\n", str)
}

func Ok() {
	color.New(color.FgGreen).Print("OK!\n")
}

func RegString(name string, value string) {
	color.New(color.FgYellow).Printf("%s", name)
	fmt.Print(" = ")
	color.New(color.FgCyan).Printf("%s\n", value)
}

func Pretty(v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func QuitFatal(err error) {
	color.New(color.FgHiRed, color.Bold).Printf("\nFatal: %s\n", err.Error())
	fmt.Print("Press Enter to exit...")
	reader := bufio.NewReader(os.Stdin)
	reader.ReadString('\n')
	os.Exit(1)
}
