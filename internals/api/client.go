package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// PushRequest represents the payload sent to the server
type PushRequest struct {
	DeviceID      string `json:"device_id"`
	EncryptedData string `json:"encrypted_data"` // base64 encoded
	EncryptedKey  string `json:"encrypted_key"`  // base64 encoded
	FileName      string `json:"file_name"`
}

// PushResponse represents the server's response
type PushResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// PushEnv sends encrypted .env data to the server
func PushEnv(serverURL, projectID string, req PushRequest) error {
	url := fmt.Sprintf("%s/projects/%s/env", serverURL, projectID)

	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("error marshaling request: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var pushResp PushResponse
	err = json.NewDecoder(resp.Body).Decode(&pushResp)
	if err != nil {
		return fmt.Errorf("error decoding response: %w", err)
	}

	if !pushResp.Success {
		return fmt.Errorf("push failed: %s", pushResp.Message)
	}

	return nil
}

// PullRequest represents the query parameters for pull
type PullRequest struct {
	DeviceID string `json:"device_id"`
}

// PullResponse represents the server's response for pull
type PullResponse struct {
	Success bool         `json:"success"`
	Message string       `json:"message"`
	Files   []PulledFile `json:"files,omitempty"`
}

// PulledFile represents an encrypted file from the server
type PulledFile struct {
	FileName      string `json:"file_name"`
	EncryptedData string `json:"encrypted_data"` // base64
	EncryptedKey  string `json:"encrypted_key"`  // base64
}

// PullEnv fetches encrypted .env data from the server
func PullEnv(serverURL, projectID, deviceID string) ([]PulledFile, error) {
	url := fmt.Sprintf("%s/projects/%s/env?device_id=%s", serverURL, projectID, deviceID)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var pullResp PullResponse
	err = json.NewDecoder(resp.Body).Decode(&pullResp)
	if err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	if !pullResp.Success {
		return nil, fmt.Errorf("pull failed: %s", pullResp.Message)
	}

	return pullResp.Files, nil
}
