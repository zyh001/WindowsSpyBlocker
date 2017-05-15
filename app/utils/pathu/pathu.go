package pathu

import (
	"os"
	"path"
	"path/filepath"

	"github.com/crazy-max/WindowsSpyBlocker/app/utils/file"
)

var Current, _ = filepath.Abs(filepath.Dir(os.Args[0]))
var Libs = path.Join(Current, "libs")
var Logs = path.Join(Current, "logs")
var Tmp = path.Join(Current, "tmp")

func init() {
	file.CreateSubfolder(Libs)
	file.CreateSubfolder(Logs)
	file.CreateSubfolder(Tmp)
}
