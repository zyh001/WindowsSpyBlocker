package dev

import (
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/crazy-max/WindowsSpyBlocker/app/bindata"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
)

func extractData(args ...string) (err error) {
	fmt.Println()

	if _, err := os.Stat(pathu.Data); err == nil {
		dataBackupPath := path.Join(pathu.Current, fmt.Sprintf("%s.%s", "data", time.Now().Format("20060102150405")))
		fmt.Printf("Backing current data folder in %s... ", strings.TrimLeft(dataBackupPath, pathu.Current))
		if err := os.Rename(pathu.Data, dataBackupPath); err != nil {
			print.Error(err)
			return nil
		}
		print.Ok()
	}

	fmt.Printf("Extracting data in %s... ", pathu.Data)
	if err := bindata.RestoreAssets(pathu.Current, "data"); err != nil {
		print.Error(err)
	}
	print.Ok()

	return nil
}
