package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

func SaveCache(filename string, cache *sync.Map) error {
	tempMap := make(map[string]time.Time)
	cache.Range(func(key, value interface{}) bool {
		if k, ok := key.(string); ok {
			if v, ok := value.(time.Time); ok {
				tempMap[k] = v
			}
		}
		return true
	})
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	return encoder.Encode(tempMap)
}

func LoadCache(filename string) *sync.Map {
	var cache sync.Map
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("No cache yet? Got error for %s: %v\n", filename, err)
		return &cache
	}
	defer file.Close()

	tempMap := make(map[string]time.Time)
	decoder := json.NewDecoder(file)
	if err = decoder.Decode(&tempMap); err != nil {
		panic(fmt.Sprintf("Could not open cache %s: %v\n", filename, err))
	}
	for k, v := range tempMap {
		cache.Store(k, v)
	}
	return &cache
}
