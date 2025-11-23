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
	"github.com/spf13/cobra"
)

// pullCmd represents the pull command
var pullCmd = &cobra.Command{
	Use:   "pull",
	Short: "Pull and decrypt .env files from the server",
	Long: `Pull the latest encrypted .env files from the EnvSync server and decrypt them locally.
The AES keys are decrypted using the device's private RSA key, then used to decrypt the data.`,
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

		// Pull from server
		files, err := api.PullEnv(projectConfig.ServerURL, projectConfig.ProjectID, deviceConfig.DeviceID)
		if err != nil {
			fmt.Printf("Error pulling from server: %v\n", err)
			return
		}

		// Process each file
		for _, file := range files {
			// Decode base64
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

			// Decrypt AES key with RSA
			aesKey, err := crypto.DecryptRSA(privateKey, encryptedKey)
			if err != nil {
				fmt.Printf("Error decrypting AES key for %s: %v\n", file.FileName, err)
				continue
			}

			// Decrypt data with AES
			data, err := crypto.DecryptAES(aesKey, encryptedData)
			if err != nil {
				fmt.Printf("Error decrypting data for %s: %v\n", file.FileName, err)
				continue
			}

			// Save to file
			filePath := filepath.Join(cwd, file.FileName)
			err = os.WriteFile(filePath, data, 0644)
			if err != nil {
				fmt.Printf("Error writing file %s: %v\n", file.FileName, err)
				continue
			}

			fmt.Printf("Successfully pulled and decrypted %s\n", file.FileName)
		}

		fmt.Println("Pull completed.")
	},
}

func init() {
	rootCmd.AddCommand(pullCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// pullCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// pullCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
