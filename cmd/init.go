/*
Copyright © 2025 Manpreet Singh <mannuvilasara@gmail.com>
*/
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/MannuVilasara/envsync/internals/config"
	"github.com/MannuVilasara/envsync/internals/crypto"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize EnvSync for the current project",
	Long: `Initialize EnvSync for the current project by creating a .envsync directory
with necessary configuration and cryptographic keys.`,
	Run: func(cmd *cobra.Command, args []string) {
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Printf("Error getting current directory: %v\n", err)
			return
		}

		envsyncDir := filepath.Join(cwd, ".envsync")
		if _, err := os.Stat(envsyncDir); !os.IsNotExist(err) {
			fmt.Println("EnvSync is already initialized in this directory.")
			return
		}

		err = os.Mkdir(envsyncDir, 0755)
		if err != nil {
			fmt.Printf("Error creating .envsync directory: %v\n", err)
			return
		}

		// Generate RSA key pair
		err = crypto.GenerateKeyPair(envsyncDir)
		if err != nil {
			fmt.Printf("Error generating key pair: %v\n", err)
			return
		}

		// Create config
		deviceConfig := &config.Config{
			DeviceID: uuid.New().String(),
			Version:  "1.0",
		}
		err = config.SaveConfig(envsyncDir, deviceConfig)
		if err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			return
		}

		// Create project config
		projectConfigPath := filepath.Join(cwd, "envsync.config.json")
		if _, err := os.Stat(projectConfigPath); os.IsNotExist(err) {
			projectConfig := &config.ProjectConfig{
				ProjectID:    uuid.New().String(),
				ServerURL:    "http://localhost:8080", // TODO: configurable
				TrackedFiles: []string{".env"},
			}
			err = config.SaveProjectConfig(cwd, projectConfig)
			if err != nil {
				fmt.Printf("Error saving project config: %v\n", err)
				return
			}
			fmt.Printf("Created envsync.config.json with default tracked files.\n")
		}

		fmt.Println("EnvSync initialized successfully.")
		fmt.Printf("Created .envsync directory with keys and config.\n")
	},
}

func init() {
	rootCmd.AddCommand(initCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// initCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// initCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
