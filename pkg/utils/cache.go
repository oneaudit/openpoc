package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// It takes hours to compute the cache
var key = []byte(os.Getenv("PRECOMPUTED_CACHE_KEY"))

func SaveCache(filename string, cache *sync.Map) error {
	// Nothing to load as there are no keys
	if len(key) == 0 {
		return nil
	}

	if cache == nil {
		return nil
	}

	tempMap := make(map[string]time.Time)
	cache.Range(func(key, value interface{}) bool {
		if k, ok := key.(string); ok {
			if v, ok := value.(time.Time); ok {
				tempMap[k] = v
			}
		}
		return true
	})

	plaintext, err := json.Marshal(tempMap)
	if err != nil {
		return nil
	}
	ciphertext := Encipher(filename, plaintext)
	if ciphertext == nil {
		return nil
	}
	return os.WriteFile(filename, ciphertext, 0644)
}

func LoadCache(filename string) *sync.Map {
	var cache sync.Map

	// Nothing to load as there are no keys
	if len(key) == 0 {
		return nil
	}

	// Load the cache
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("No cache yet? Got error for %s: %v\n", filename, err)
		return &cache
	}
	defer file.Close()

	// Read the cache
	ciphertext, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("Could not read %s: %v\n", filename, err)
		return nil
	}

	plaintext := Decipher(filename, ciphertext)
	if plaintext == nil {
		return nil
	}

	// Parse the cache
	tempMap := make(map[string]time.Time)
	if err = json.Unmarshal(plaintext, &tempMap); err != nil {
		fmt.Printf("Could not open cache %s: %v\n", filename, err)
		return nil
	}
	for k, v := range tempMap {
		cache.Store(k, v)
	}
	fmt.Printf("Loaded cache for %s\n", filename)
	return &cache
}

func Decipher(filename string, ciphertext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("Could not create cipher %s: %v\n", filename, err)
		return nil
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("Could not create gcm %s: %v\n", filename, err)
		return nil
	}
	nonceSize := aesGCM.NonceSize()
	nonce, cipherData := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, cipherData, nil)
	if err != nil {
		fmt.Printf("Could not read data %s: %v\n", filename, err)
		return nil

	}
	return plaintext
}

func Encipher(filename string, jsonData []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("Could not create cipher %s: %v\n", filename, err)
		return nil
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("Could not create gcm %s: %v\n", filename, err)
		return nil
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		fmt.Printf("Could not read nonce %s: %v\n", filename, err)
		return nil
	}

	return aesGCM.Seal(nonce, nonce, jsonData, nil)
}
