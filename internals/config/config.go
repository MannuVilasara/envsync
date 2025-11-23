package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config represents the device-specific configuration
type Config struct {
	DeviceID string `json:"device_id"`
	Version  string `json:"version"`
}

// LoadConfig loads the config from the .envsync directory
func LoadConfig(envsyncDir string) (*Config, error) {
	configPath := filepath.Join(envsyncDir, "config.json")
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("error opening config file: %w", err)
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return nil, fmt.Errorf("error decoding config: %w", err)
	}

	return &config, nil
}

// SaveConfig saves the config to the .envsync directory
func SaveConfig(envsyncDir string, config *Config) error {
	configPath := filepath.Join(envsyncDir, "config.json")
	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("error creating config file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(config)
	if err != nil {
		return fmt.Errorf("error encoding config: %w", err)
	}

	return nil
}

// ProjectConfig represents the project-specific configuration
type ProjectConfig struct {
	ProjectID    string   `json:"project_id"`
	ServerURL    string   `json:"server_url,omitempty"`
	TrackedFiles []string `json:"tracked_files"`
}

// LoadProjectConfig loads the project config from the root directory
func LoadProjectConfig(rootDir string) (*ProjectConfig, error) {
	configPath := filepath.Join(rootDir, "envsync.config.json")
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("error opening project config file: %w", err)
	}
	defer file.Close()

	var config ProjectConfig
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return nil, fmt.Errorf("error decoding project config: %w", err)
	}

	return &config, nil
}

// SaveProjectConfig saves the project config to the root directory
func SaveProjectConfig(rootDir string, config *ProjectConfig) error {
	configPath := filepath.Join(rootDir, "envsync.config.json")
	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("error creating project config file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(config)
	if err != nil {
		return fmt.Errorf("error encoding project config: %w", err)
	}

	return nil
}
