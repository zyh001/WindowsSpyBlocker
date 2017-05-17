package file

import (
	"archive/zip"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
)

// CreateFile creates a file and print status
func CreateFile(file string) error {
	w, err := os.Create(file)
	if err != nil {
		print.Error(err)
		return err
	}

	defer w.Close()
	print.Ok()
	return nil
}

// CreateSubfolder creates a folder recusively
func CreateSubfolder(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = os.MkdirAll(path, 777)
		if err != nil {
			return err
		}
	}
	return nil
}

// Unzip a file in a destination path
// https://stackoverflow.com/questions/20357223/easy-way-to-unzip-file-with-golang
func Unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}

	defer func() {
		if err := r.Close(); err != nil {
			panic(err)
		}
	}()

	os.MkdirAll(dest, 0755)

	// Closure to address file descriptors issue with all the deferred .Close() methods
	extractAndWriteFile := func(f *zip.File) error {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if err := rc.Close(); err != nil {
				panic(err)
			}
		}()

		thePath := filepath.Join(dest, f.Name)

		if f.FileInfo().IsDir() {
			os.MkdirAll(thePath, f.Mode())
		} else {
			os.MkdirAll(filepath.Dir(thePath), f.Mode())
			f, err := os.OpenFile(thePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}

			defer func() {
				if err := f.Close(); err != nil {
					panic(err)
				}
			}()

			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}

		return nil
	}

	for _, f := range r.File {
		err := extractAndWriteFile(f)
		if err != nil {
			return err
		}
	}

	return nil
}

// RemoveFile removes a file
func RemoveFile(filename string) error {
	if _, err := os.Stat(filename); err == nil {
		err := os.Remove(filename)
		if err != nil {
			print.Error(err)
			return err
		}
	} else {
		return errors.New("File not found")
	}
	return nil
}

// CopyFile copy a file
func CopyFile(src string, dest string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		return err
	}

	err = destFile.Sync()
	if err != nil {
		return err
	}

	return nil
}
