package main

import (
	"fmt"
	"openpoc/pkg/types"
	"openpoc/pkg/utils"
	"os"
	"path/filepath"
)

var (
	exploitDB = types.Target{
		URL:       "https://gitlab.com/exploit-database/exploitdb.git",
		Folder:    "datasources/exploitdb",
		Branch:    "main",
		Skip:      false,
		Completed: false,
	}
)

func main() {
	//
	// ExploitDB
	//
	if !exploitDB.Skip {
		// Clone repository (shallow and no checkout)
		err := utils.GitClone("", exploitDB.URL, exploitDB.Folder, 1, "--no-checkout")
		if err != nil {
			fmt.Printf("Error cloning %s: %v\n", exploitDB.URL, err)
		} else {
			// We will only plan to clone specific files
			if err = utils.RunCommandDir(exploitDB.Folder, "git", "config", "core.sparseCheckout", "true"); err == nil {
				// We will only fetch the file below
				sparsePath := filepath.Join(exploitDB.Folder, ".git", "info", "sparse-checkout")
				if err = os.WriteFile(sparsePath, []byte("files_exploits.csv"+"\n"), 0644); err == nil {
					// We can process with the fetch
					if err = utils.RunCommandDir(exploitDB.Folder, "git", "checkout", exploitDB.Branch); err != nil {
						fmt.Printf("Error setting sparseCheckout file: %v\n", err)
					} else {
						exploitDB.Completed = true
					}
				} else {
					fmt.Printf("Error setting sparseCheckout file: %v\n", err)
				}
			} else {
				fmt.Printf("Error setting sparseCheckout: %v\n", err)
			}
		}
	}
}
