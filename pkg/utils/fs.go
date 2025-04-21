package utils

import (
	"os"
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
	return diff <= duration*time.Hour
}
