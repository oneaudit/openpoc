package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
		Range:     12,
	}
	exploitDBFilename = "files_exploits.csv"

	inTheWild = types.Target{
		URL:       "https://inthewild.io/api/exploits",
		Folder:    "datasources/inthewild",
		Branch:    "",
		Completed: true,
		Range:     48,
	}
	inTheWildFilename = "pocs.json"
)

func main() {
	var err error
	yearMap := make(map[string]map[string]*types.AggregatorResult)

	//
	// ExploitDB
	//
	var newExploitDB []*types.ExploitDB
	exploitDBFile := filepath.Join(exploitDB.Folder, exploitDBFilename)
	exploitDB.Completed = utils.WasModifiedWithin(exploitDBFile, exploitDB.Range)

	if !exploitDB.Completed {
		// Clone repository (shallow and no checkout)
		if err = utils.GitClone("", exploitDB.URL, exploitDB.Folder, 1, "--no-checkout"); err == nil {
			// We will only plan to clone specific files
			if err = utils.RunCommandDir(exploitDB.Folder, "git", "config", "core.sparseCheckout", "true"); err == nil {
				// We will only fetch the file below
				sparsePath := filepath.Join(exploitDB.Folder, ".git", "info", "sparse-checkout")
				if err = os.WriteFile(sparsePath, []byte(exploitDBFilename+"\n"), 0644); err == nil {
					// We can process with the fetch
					if err = utils.RunCommandDir(exploitDB.Folder, "git", "checkout", exploitDB.Branch); err == nil {
						if newExploitDB, err = providers.ParseExploitDB(exploitDBFile); err == nil {
							exploitDB.Completed = true
						} else {
							fmt.Printf("Error parsing database %s: %v\n", exploitDBFile, err)
						}
					} else {
						fmt.Printf("Error setting sparseCheckout file for exploitdb: %v\n", err)
					}
				} else {
					fmt.Printf("Error setting sparseCheckout file for exploitdb: %v\n", err)
				}
			} else {
				fmt.Printf("Error setting sparseCheckout for exploitdb: %v\n", err)
			}
		} else {
			fmt.Printf("Error cloning %s: %v\n", exploitDB.URL, err)
		}
	} else {
		if newExploitDB, err = providers.ParseExploitDB(exploitDBFile); err == nil {
			exploitDB.Completed = true
		} else {
			fmt.Printf("Error parsing exploitdb database %s: %v\n", exploitDBFile, err)
		}
	}

	//
	// InTheWild
	//
	var newInTheWild []*types.InTheWild
	inTheWildFile := filepath.Join(inTheWild.Folder, inTheWildFilename)
	inTheWild.Completed = utils.WasModifiedWithin(inTheWildFile, inTheWild.Range)

	if !inTheWild.Completed {
		var response *http.Response
		var outFile *os.File
		// Create the folder to store the file
		if err = os.MkdirAll(inTheWild.Folder, 0755); err == nil {
			// Fetch the data from the API
			if response, err = http.Get(inTheWild.URL); err == nil {
				defer response.Body.Close()
				// Ensure the response was successful
				if response.StatusCode == http.StatusOK {
					// Store the response
					outFile, err = os.Create(inTheWildFile)
					if err == nil {
						if _, err = io.Copy(outFile, response.Body); err == nil {
							if newInTheWild, err = providers.ParseInTheWild(inTheWildFile); err == nil {
								inTheWild.Completed = true
							} else {
								fmt.Printf("Error parsing database %s: %v\n", inTheWildFile, err)
							}
						} else {
							fmt.Printf("Error storing response in file %s: %v\n", inTheWildFile, err)
						}
						outFile.Close()
					} else {
						fmt.Printf("Error creating file: %v\n", err)
					}
				} else {
					fmt.Printf("Unexpected status code for in the wild: %d", response.StatusCode)
				}
			} else {
				fmt.Printf("Could not fetch %s: %v\n", inTheWild.URL, err)
			}
		} else {
			fmt.Printf("Error creating in the wild folder: %v\n", err)
		}
	} else {
		if newInTheWild, err = providers.ParseInTheWild(inTheWildFile); err == nil {
			inTheWild.Completed = true
		} else {
			fmt.Printf("Error parsing database %s: %v\n", inTheWildFile, err)
		}
	}

	//
	// Add to the map
	//
	for _, exploit := range newExploitDB {
		year, jsonFilePath := addToYearMap(exploit, &yearMap)
		if year != "" && jsonFilePath != "" {
			yearMap[year][jsonFilePath].ExploitDB = append(yearMap[year][jsonFilePath].ExploitDB, *exploit)
		}
	}
	for _, exploit := range newInTheWild {
		year, jsonFilePath := addToYearMap(exploit, &yearMap)
		if year != "" && jsonFilePath != "" {
			yearMap[year][jsonFilePath].InTheWild = append(yearMap[year][jsonFilePath].InTheWild, *exploit)
		}
	}

	//
	// Write to Disk
	//
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
				finalResult = MergeAggregatorResults(result, &existingResult)
			} else {
				finalResult = result
			}

			// Create OpenPoC which is a sort of summary of all sources
			merger := make(map[string]*types.OpenpocProduct)
			for _, exploit := range finalResult.ExploitDB {
				addToMerger(&exploit, &merger)
			}
			for _, exploit := range finalResult.InTheWild {
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
	if !inTheWild.Completed {
		newResult.InTheWild = oldResult.InTheWild
	}
	return newResult
}

func addToYearMap[T types.OpenPocMetadata](exploit T, yearMap *map[string]map[string]*types.AggregatorResult) (string, string) {
	year := utils.GetCVEYear(exploit.GetCve())
	if year == "" {
		fmt.Printf("[WRN] Error parsing: <%s>\n", exploit.GetCve())
		return "", ""
	}
	if _, ok := (*yearMap)[year]; !ok {
		(*yearMap)[year] = make(map[string]*types.AggregatorResult)
	}
	// While there is a regex, we add some protection just in case
	jsonFilePath := filepath.Join(filepath.Base(year), filepath.Base(exploit.GetCve()+".json"))
	if _, ok := (*yearMap)[year][jsonFilePath]; !ok {
		(*yearMap)[year][jsonFilePath] = &types.AggregatorResult{
			InTheWild: []types.InTheWild{},
			ExploitDB: []types.ExploitDB{},
			Openpoc:   []types.OpenpocProduct{},
		}
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
