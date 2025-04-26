package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func WasModifiedWithin(filePath string, duration time.Duration) bool {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return false
	}
	modTime := fileInfo.ModTime()
	currentTime := time.Now()
	diff := currentTime.Sub(modTime)
	return diff <= (duration-1)*time.Hour
}

func ProcessFiles(rootDir string, process func(string) error) error {
	return filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(rootDir, path)
		if err != nil {
			return err
		}
		return process(filepath.Join(rootDir, relPath))
	})
}

func GetDirectories() (dirs []string) {
	currentYear := time.Now().Year()
	startYear := 1999
	for year := currentYear; year >= startYear; year-- {
		dir := fmt.Sprintf("%04d", year)
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}
