package utils

import (
	"os"
	"os/exec"
)

func RunCommand(dir string, name string, args []string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func RunCommandDir(dir string, cmd string, args ...string) error {
	return RunCommand(dir, cmd, args)
}
