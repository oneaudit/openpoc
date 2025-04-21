package main

import (
	"encoding/json"
	"fmt"
	"openpoc/pkg/providers"
	"openpoc/pkg/types"
	"openpoc/pkg/utils"
	"os"
	"path/filepath"
)

const (
	isTesting  = true
	indexLimit = 10
)

var (
	exploitDB = types.Target{
		URL:       "https://gitlab.com/exploit-database/exploitdb.git",
		Folder:    "datasources/exploitdb",
		Branch:    "main",
		Completed: true,
	}
	exploitDBFilename = "files_exploits.csv"
)

func main() {
	//
	// ExploitDB
	//
	var newExploitDB []*types.ExploitDB
	if !exploitDB.Completed {
		// Clone repository (shallow and no checkout)
		err := utils.GitClone("", exploitDB.URL, exploitDB.Folder, 1, "--no-checkout")
		if err != nil {
			fmt.Printf("Error cloning %s: %v\n", exploitDB.URL, err)
		} else {
			// We will only plan to clone specific files
			if err = utils.RunCommandDir(exploitDB.Folder, "git", "config", "core.sparseCheckout", "true"); err == nil {
				// We will only fetch the file below
				sparsePath := filepath.Join(exploitDB.Folder, ".git", "info", "sparse-checkout")
				if err = os.WriteFile(sparsePath, []byte(exploitDBFilename+"\n"), 0644); err == nil {
					// We can process with the fetch
					if err = utils.RunCommandDir(exploitDB.Folder, "git", "checkout", exploitDB.Branch); err == nil {
						exploitDBFile := filepath.Join(exploitDB.Folder, exploitDBFilename)
						if newExploitDB, err = providers.ParseExploitDB(exploitDBFile); err == nil {
							exploitDB.Completed = true
						} else {
							fmt.Printf("Error parsing database %s: %v\n", exploitDBFile, err)
						}
					} else {
						fmt.Printf("Error setting sparseCheckout file: %v\n", err)
					}
				} else {
					fmt.Printf("Error setting sparseCheckout file: %v\n", err)
				}
			} else {
				fmt.Printf("Error setting sparseCheckout: %v\n", err)
			}
		}
	} else {
		var err error
		exploitDBFile := filepath.Join(exploitDB.Folder, exploitDBFilename)
		if newExploitDB, err = providers.ParseExploitDB(exploitDBFile); err == nil {
			exploitDB.Completed = true
		} else {
			fmt.Printf("Error parsing database %s: %v\n", exploitDBFile, err)
		}
	}

	yearMap := make(map[string]map[string]*types.AggregatorResult)
	for _, exploit := range newExploitDB {
		year, jsonFilePath := addToYearMap(exploit, &yearMap)
		if year != "" && jsonFilePath != "" {
			yearMap[year][jsonFilePath].ExploitDB = append(yearMap[year][jsonFilePath].ExploitDB, *exploit)
		}
	}

	// Write to Disk
	i := 0
	for year, results := range yearMap {
		err := os.MkdirAll(year, 0755)
		if err != nil {
			fmt.Printf("error creating directory: %v", err)
			return
		}
		for jsonFilePath, result := range results {
			var finalResult *types.AggregatorResult
			file, err := os.OpenFile(jsonFilePath, os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				fmt.Printf("error opening JSON file: %v\n", err)
				return
			}
			info, err := file.Stat()
			if err != nil {
				file.Close()
				fmt.Printf("error stating file: %v\n", err)
				return
			}
			if info.Size() > 0 {
				var existingResult types.AggregatorResult
				decoder := json.NewDecoder(file)
				err = decoder.Decode(&existingResult)
				if err != nil {
					file.Close()
					fmt.Printf("error decoding existing JSON file: %v\n", err)
					return
				}
				finalResult = MergeAggregatorResults(finalResult, &existingResult)
			} else {
				finalResult = result
			}

			// Create OpenPoC which is a sort of summary of all sources
			merger := make(map[string]*types.OpenpocProduct)
			for _, exploit := range finalResult.ExploitDB {
				addToMerger(&exploit, &merger)
			}
			for _, url := range merger {
				finalResult.Openpoc = append(finalResult.Openpoc, *url)
			}

			err = file.Truncate(0)
			if err != nil {
				file.Close()
				fmt.Printf("error truncating file: %v\n", err)
				return
			}
			_, err = file.Seek(0, 0)
			if err != nil {
				file.Close()
				fmt.Printf("error seeking to file start: %v\n", err)
				return
			}

			encoder := json.NewEncoder(file)
			encoder.SetIndent("", "  ")
			err = encoder.Encode(finalResult)
			file.Close()
			if err != nil {
				fmt.Printf("error writing to JSON file: %v\n", err)
				return
			}

			i++
			if isTesting && i >= indexLimit {
				break
			}
		}
	}
}

func MergeAggregatorResults(newResult *types.AggregatorResult, oldResult *types.AggregatorResult) *types.AggregatorResult {
	if !exploitDB.Completed {
		newResult.ExploitDB = oldResult.ExploitDB
	}
	return newResult
}

func addToYearMap[T types.OpenPocMetadata](exploit T, yearMap *map[string]map[string]*types.AggregatorResult) (string, string) {
	year := utils.GetCVEYear(exploit.GetCve())
	if year == "" {
		fmt.Printf("[WRN] Error parsing: %s\n", exploit.GetCve())
		return "", ""
	}
	if _, ok := (*yearMap)[year]; !ok {
		(*yearMap)[year] = make(map[string]*types.AggregatorResult)
	}
	// While there is a regex, we add some protection just in case
	jsonFilePath := filepath.Join(filepath.Base(year), filepath.Base(exploit.GetCve()+".json"))
	if _, ok := (*yearMap)[year][jsonFilePath]; !ok {
		(*yearMap)[year][jsonFilePath] = &types.AggregatorResult{}
	}
	return year, jsonFilePath
}

func addToMerger[T types.OpenPocMetadata](exploit T, merger *map[string]*types.OpenpocProduct) {
	value, found := (*merger)[exploit.GetURL()]
	if !found {
		(*merger)[exploit.GetURL()] = &types.OpenpocProduct{
			Cve:         exploit.GetCve(),
			URL:         exploit.GetURL(),
			AddedAt:     exploit.AddedAt(),
			Trustworthy: exploit.IsTrustworthy(),
		}
	} else if !value.Trustworthy {
		value.Trustworthy = exploit.IsTrustworthy()
	}
}
