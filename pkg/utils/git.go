package utils

import (
	"strconv"
)

// we never use go-git, especially for large repositories
// as it didn't work well with shallow clones

func GitClone(pwd string, url string, dest string, depth int, extraArgs ...string) error {
	var args []string
	args = append(args, "clone")
	if depth >= 1 {
		args = append(args, "--depth", strconv.Itoa(depth))
	}
	args = append(args, extraArgs...)
	args = append(args, url, dest)
	err := RunCommand(pwd, "git", args)
	return err
}
