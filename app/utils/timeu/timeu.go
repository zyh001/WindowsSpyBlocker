package timeu

import (
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/hako/durafmt"
)

// Track execution time
func Track(start time.Time) {
	fmt.Print("\nTime spent: ")
	color.New(color.FgMagenta).Printf("%s\n", durafmt.Parse(time.Since(start)))
}
