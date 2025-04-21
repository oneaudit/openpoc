package utils

import (
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
