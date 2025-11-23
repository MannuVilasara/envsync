/*
Copyright © 2025 Manpreet Singh <mannuvilasara@gmail.com>
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

// pushCmd represents the push command
var pushCmd = &cobra.Command{
	Use:   "push",
	Short: "Push encrypted .env files to the server",
	Long: `Push the tracked .env files to the EnvSync server after encrypting them locally.
The files are encrypted with AES-256-GCM, and the AES key is encrypted with RSA.`,
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

		// Load public key
		publicKeyPath := filepath.Join(envsyncDir, "public.pem")
		publicKey, err := crypto.LoadPublicKey(publicKeyPath)
		if err != nil {
			fmt.Printf("Error loading public key: %v\n", err)
			return
		}

		// Process each tracked file
		for _, fileName := range projectConfig.TrackedFiles {
			filePath := filepath.Join(cwd, fileName)
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				fmt.Printf("Tracked file %s does not exist, skipping.\n", fileName)
				continue
			}

			// Read file content
			data, err := os.ReadFile(filePath)
			if err != nil {
				fmt.Printf("Error reading file %s: %v\n", fileName, err)
				continue
			}

			// Generate AES key
			aesKey, err := crypto.GenerateAESKey()
			if err != nil {
				fmt.Printf("Error generating AES key: %v\n", err)
				continue
			}

			// Encrypt data with AES
			encryptedData, err := crypto.EncryptAES(aesKey, data)
			if err != nil {
				fmt.Printf("Error encrypting data: %v\n", err)
				continue
			}

			// Encrypt AES key with RSA
			encryptedKey, err := crypto.EncryptRSA(publicKey, aesKey)
			if err != nil {
				fmt.Printf("Error encrypting AES key: %v\n", err)
				continue
			}

			// Encode to base64 for JSON
			encryptedDataB64 := base64.StdEncoding.EncodeToString(encryptedData)
			encryptedKeyB64 := base64.StdEncoding.EncodeToString(encryptedKey)

			// Push to server
			pushReq := api.PushRequest{
				DeviceID:      deviceConfig.DeviceID,
				EncryptedData: encryptedDataB64,
				EncryptedKey:  encryptedKeyB64,
				FileName:      fileName,
			}

			err = api.PushEnv(projectConfig.ServerURL, projectConfig.ProjectID, pushReq)
			if err != nil {
				fmt.Printf("Error pushing %s: %v\n", fileName, err)
				continue
			}

			fmt.Printf("Successfully pushed %s\n", fileName)
		}

		fmt.Println("Push completed.")
	},
}

func init() {
	rootCmd.AddCommand(pushCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// pushCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// pushCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
