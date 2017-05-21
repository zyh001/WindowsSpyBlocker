package pathu

import (
	"os"
	"path"
	"path/filepath"

	"github.com/crazy-max/WindowsSpyBlocker/app/utils/file"
)

// List of paths relative to the executable path
var (
	Current, _ = filepath.Abs(filepath.Dir(os.Args[0]))
	Data       = path.Join(Current, "data")
	Libs       = path.Join(Current, "libs")
	Logs       = path.Join(Current, "logs")
	Tmp        = path.Join(Current, "tmp")
)

func init() {
	file.CreateSubfolder(Libs)
	file.CreateSubfolder(Logs)
	file.CreateSubfolder(Tmp)
}
