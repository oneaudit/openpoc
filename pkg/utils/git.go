package utils

import (
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// we never use go-git, especially for large repositories
// as it didn't work well with shallow clones

func GitClone(pwd string, url string, dest string, depth int, branch string, extraArgs ...string) error {
	var args []string
	args = append(args, "clone")
	if depth >= 1 {
		args = append(args, "--depth", strconv.Itoa(depth))
	}
	if branch != "" {
		args = append(args, "--branch", branch)
	}
	args = append(args, extraArgs...)
	args = append(args, url, dest)
	err := RunCommand(pwd, "git", args)
	return err
}

func GetDateFromGitFile(pwd string, target string, cache *sync.Map, defaultDate time.Time) (parsedTime time.Time) {
	// Load From Cache
	if cache == nil {
		return defaultDate
	}

	target = filepath.ToSlash(target)

	if cachedTime, found := cache.Load(target); found {
		parsedTime = cachedTime.(time.Time)
		return
	} else {
		parsedTime = defaultDate
	}
	// Get the author date of the first commit for this file
	cmd := exec.Command("git", "log", "--diff-filter=A", "--format=%ad", "--date=iso", "--", target)
	cmd.Dir = pwd
	raw, err := cmd.Output()
	if err != nil {
		return
	}
	result := strings.Split(string(raw), "\n")
	if len(result) < 2 {
		return
	}
	dateStr := result[len(result)-2]
	parts := strings.Split(dateStr, " ")
	if len(parts) != 3 {
		return
	}
	dateStr = strings.Join(parts[:len(parts)-1], " ")
	parsedTime, err = time.Parse(time.DateTime, dateStr)
	if err != nil {
		return
	}
	cache.Store(target, parsedTime)
	return
}
