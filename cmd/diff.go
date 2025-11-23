/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/MannuVilasara/envsync/internals/api"
	"github.com/MannuVilasara/envsync/internals/config"
	"github.com/MannuVilasara/envsync/internals/crypto"
	"github.com/MannuVilasara/envsync/internals/utils"
	"github.com/spf13/cobra"
)

// diffCmd represents the diff command
var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Show differences between local and remote .env files",
	Long: `Compare the local .env files with the latest versions from the server.
Shows added, removed, or modified environment variables.`,
	Run: func(cmd *cobra.Command, args []string) {
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Printf("Error getting current directory: %v\n", err)
			return
		}

		envsyncDir := filepath.Join(cwd, ".envsync")
		if _, err := os.Stat(envsyncDir); os.IsNotExist(err) {
			fmt.Println("EnvSync is not initialized in this directory. Run 'envsync init' first.")
			return
		}

		// Load configs
		projectConfig, err := config.LoadProjectConfig(cwd)
		if err != nil {
			fmt.Printf("Error loading project config: %v\n", err)
			return
		}

		deviceConfig, err := config.LoadConfig(envsyncDir)
		if err != nil {
			fmt.Printf("Error loading device config: %v\n", err)
			return
		}

		if projectConfig.ServerURL == "" {
			fmt.Println("Server URL not configured. Please set server_url in envsync.config.json")
			return
		}

		// Load private key
		privateKeyPath := filepath.Join(envsyncDir, "private.pem")
		privateKey, err := crypto.LoadPrivateKey(privateKeyPath)
		if err != nil {
			fmt.Printf("Error loading private key: %v\n", err)
			return
		}

		// Pull remote files
		remoteFiles, err := api.PullEnv(projectConfig.ServerURL, projectConfig.ProjectID, deviceConfig.DeviceID)
		if err != nil {
			fmt.Printf("Error pulling from server: %v\n", err)
			return
		}

		// Create map of remote files
		remoteData := make(map[string]utils.EnvData)
		for _, file := range remoteFiles {
			// Decode and decrypt
			encryptedData, err := base64.StdEncoding.DecodeString(file.EncryptedData)
			if err != nil {
				fmt.Printf("Error decoding encrypted data for %s: %v\n", file.FileName, err)
				continue
			}

			encryptedKey, err := base64.StdEncoding.DecodeString(file.EncryptedKey)
			if err != nil {
				fmt.Printf("Error decoding encrypted key for %s: %v\n", file.FileName, err)
				continue
			}

			aesKey, err := crypto.DecryptRSA(privateKey, encryptedKey)
			if err != nil {
				fmt.Printf("Error decrypting AES key for %s: %v\n", file.FileName, err)
				continue
			}

			data, err := crypto.DecryptAES(aesKey, encryptedData)
			if err != nil {
				fmt.Printf("Error decrypting data for %s: %v\n", file.FileName, err)
				continue
			}

			// Parse as env
			envData, err := utils.ParseEnvData(string(data))
			if err != nil {
				fmt.Printf("Error parsing env data for %s: %v\n", file.FileName, err)
				continue
			}

			remoteData[file.FileName] = envData
		}

		// Compare with local files
		hasDiff := false
		for _, fileName := range projectConfig.TrackedFiles {
			localPath := filepath.Join(cwd, fileName)
			localData, err := utils.LoadEnvFile(localPath)
			if err != nil {
				fmt.Printf("Error loading local file %s: %v\n", fileName, err)
				continue
			}

			remoteDataForFile, exists := remoteData[fileName]
			if !exists {
				fmt.Printf("File %s exists locally but not remotely\n", fileName)
				hasDiff = true
				continue
			}

			// Compare
			diffs := compareEnvData(localData, remoteDataForFile)
			if len(diffs) > 0 {
				hasDiff = true
				fmt.Printf("Differences in %s:\n", fileName)
				for _, diff := range diffs {
					fmt.Printf("  %s\n", diff)
				}
			}
		}

		// Check for remote files not tracked locally
		for fileName := range remoteData {
			found := false
			for _, tracked := range projectConfig.TrackedFiles {
				if tracked == fileName {
					found = true
					break
				}
			}
			if !found {
				fmt.Printf("File %s exists remotely but not tracked locally\n", fileName)
				hasDiff = true
			}
		}

		if !hasDiff {
			fmt.Println("No differences found.")
		}
	},
}

// compareEnvData compares two EnvData maps and returns a list of differences
func compareEnvData(local, remote utils.EnvData) []string {
	var diffs []string

	// Check for added/modified in local
	for key, localVal := range local {
		if remoteVal, exists := remote[key]; !exists {
			diffs = append(diffs, fmt.Sprintf("+ %s=%s (added locally)", key, localVal))
		} else if localVal != remoteVal {
			diffs = append(diffs, fmt.Sprintf("~ %s: local='%s', remote='%s'", key, localVal, remoteVal))
		}
	}

	// Check for removed in local
	for key, remoteVal := range remote {
		if _, exists := local[key]; !exists {
			diffs = append(diffs, fmt.Sprintf("- %s=%s (removed locally)", key, remoteVal))
		}
	}

	return diffs
}

func init() {
	rootCmd.AddCommand(diffCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// diffCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// diffCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
