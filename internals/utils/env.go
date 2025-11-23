package utils

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// EnvData represents the parsed .env file content
type EnvData map[string]string

// LoadEnvFile loads and parses a .env file
func LoadEnvFile(filePath string) (EnvData, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening env file: %w", err)
	}
	defer file.Close()

	envData := make(EnvData)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue // skip invalid lines
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		envData[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading env file: %w", err)
	}

	return envData, nil
}

// SaveEnvFile saves EnvData to a .env file
func SaveEnvFile(filePath string, envData EnvData) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("error creating directory: %w", err)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("error creating env file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for key, value := range envData {
		_, err := writer.WriteString(fmt.Sprintf("%s=%s\n", key, value))
		if err != nil {
			return fmt.Errorf("error writing to env file: %w", err)
		}
	}

	err = writer.Flush()
	if err != nil {
		return fmt.Errorf("error flushing env file: %w", err)
	}

	return nil
}

// ParseEnvData parses a string containing .env content into EnvData
func ParseEnvData(content string) (EnvData, error) {
	envData := make(EnvData)
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue // skip invalid lines
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		envData[key] = value
	}

	return envData, nil
}