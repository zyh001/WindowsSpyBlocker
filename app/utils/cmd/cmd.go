package cmd

import (
	"bytes"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows"
)

// Options of command
type Options struct {
	Command    string
	Args       []string
	WorkingDir string
	HideWindow bool
}

// Result of command
type Result struct {
	Options  Options
	ExitCode int32
	Stdout   string
	Stderr   string
}

// Exec command wrapper
func Exec(options Options) (Result, error) {
	result := Result{
		Options:  options,
		ExitCode: -1,
	}

	cmd := exec.Command(options.Command, options.Args...)
	cmdStdout := &bytes.Buffer{}
	cmdStderr := &bytes.Buffer{}
	cmd.Stdout = cmdStdout
	cmd.Stderr = cmdStderr
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: options.HideWindow}

	if options.WorkingDir != "" {
		cmd.Dir = options.WorkingDir
	}

	if err := cmd.Start(); err != nil {
		return result, err
	}

	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(windows.WaitStatus); ok {
				result.ExitCode = int32(status.ExitStatus())
			}
		}
	} else {
		result.ExitCode = 0
	}

	result.Stdout = strings.TrimSpace(cmdStdout.String())
	result.Stderr = strings.TrimSpace(cmdStderr.String())
	return result, nil
}
