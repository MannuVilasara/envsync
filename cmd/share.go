package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/MannuVilasara/envsync/internals/config"
	"github.com/spf13/cobra"
)

// ShareContext holds common configuration for share operations
type ShareContext struct {
	CWD           string
	EnvSyncDir    string
	ProjectConfig *config.ProjectConfig
	DeviceConfig  *config.Config
}

// APIResponse represents a standard API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// InvitationResponse represents the response from creating an invitation
type InvitationResponse struct {
	Success         bool      `json:"success"`
	InvitationCode  string    `json:"invitation_code"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// MemberInfo represents project member information
type MemberInfo struct {
	DeviceID  string    `json:"device_id"`
	Role      string    `json:"role"`
	AddedAt   time.Time `json:"added_at"`
	PublicKey string    `json:"public_key"`
}

var shareCmd = &cobra.Command{
	Use:   "share",
	Short: "Manage project sharing and collaboration",
	Long:  `Share projects with team members, accept invitations, and manage project access.`,
}

var inviteCmd = &cobra.Command{
	Use:   "invite [email]",
	Short: "Create an invitation for a team member to join the project",
	Long: `Generate an invitation code that can be shared with a team member.
The invitation allows them to join the project and access shared .env files.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runInvite,
}

var acceptCmd = &cobra.Command{
	Use:   "accept <invitation-code>",
	Short: "Accept an invitation to join a shared project",
	Long:  `Use an invitation code to join a project shared by another team member.`,
	Args:  cobra.ExactArgs(1),
	RunE: runAccept,
}

var membersCmd = &cobra.Command{
	Use:   "members",
	Short: "List all members of the current project",
	Long:  `Display all team members who have access to the current project.`,
	RunE: runMembers,
}

var revokeCmd = &cobra.Command{
	Use:   "revoke <device-id>",
	Short: "Remove a team member from the project (owner only)",
	Long:  `Remove a team member's access to the project. Only project owners can perform this action.`,
	Args:  cobra.ExactArgs(1),
	RunE: runRevoke,
}

func init() {
	rootCmd.AddCommand(shareCmd)
	shareCmd.AddCommand(inviteCmd)
	shareCmd.AddCommand(acceptCmd)
	shareCmd.AddCommand(membersCmd)
	shareCmd.AddCommand(revokeCmd)
}

// loadShareContext loads and validates the share context
func loadShareContext() (*ShareContext, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("error getting current directory: %w", err)
	}

	envsyncDir := filepath.Join(cwd, ".envsync")
	if _, err := os.Stat(envsyncDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("EnvSync is not initialized in this directory. Run 'envsync init' first")
	}

	projectConfig, err := config.LoadProjectConfig(cwd)
	if err != nil {
		return nil, fmt.Errorf("failed to load project config: %w", err)
	}

	deviceConfig, err := config.LoadConfig(envsyncDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load device config: %w", err)
	}

	return &ShareContext{
		CWD:           cwd,
		EnvSyncDir:    envsyncDir,
		ProjectConfig: projectConfig,
		DeviceConfig:  deviceConfig,
	}, nil
}

// makeAPIRequest performs an HTTP request and handles common response patterns
func makeAPIRequest(method, url string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

// handleAPIResponse processes API responses and returns structured data
func handleAPIResponse(resp *http.Response, target interface{}) error {
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
	}

	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	return nil
}

func runInvite(cmd *cobra.Command, args []string) error {
	ctx, err := loadShareContext()
	if err != nil {
		return err
	}

	var inviteeEmail string
	if len(args) > 0 {
		inviteeEmail = args[0]
	}

	reqBody := map[string]interface{}{
		"device_id": ctx.DeviceConfig.DeviceID,
	}
	if inviteeEmail != "" {
		reqBody["invitee_email"] = inviteeEmail
	}

	url := fmt.Sprintf("%s/projects/%s/invite", ctx.ProjectConfig.ServerURL, ctx.ProjectConfig.ProjectID)
	resp, err := makeAPIRequest(http.MethodPost, url, reqBody)
	if err != nil {
		return err
	}

	var response InvitationResponse
	if err := handleAPIResponse(resp, &response); err != nil {
		return err
	}

	if !response.Success {
		return fmt.Errorf("invitation creation failed")
	}

	fmt.Printf("Invitation created successfully!\n")
	fmt.Printf("Invitation Code: %s\n", response.InvitationCode)
	if inviteeEmail != "" {
		fmt.Printf("Send this code to: %s\n", inviteeEmail)
	}
	fmt.Println("\nTeam members can use this code to join the project:")
	fmt.Printf("envsync share accept %s\n", response.InvitationCode)

	return nil
}

func runAccept(cmd *cobra.Command, args []string) error {
	invitationCode := args[0]

	ctx, err := loadShareContext()
	if err != nil {
		return err
	}

	// Extract project ID from invitation code
	projectID, err := getProjectIDFromInvitation(ctx.ProjectConfig.ServerURL, invitationCode)
	if err != nil {
		return fmt.Errorf("failed to get project info: %w", err)
	}

	// Load public key
	publicKeyPath := filepath.Join(ctx.EnvSyncDir, "public.pem")
	publicKeyData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key: %w", err)
	}

	reqBody := map[string]string{
		"invitation_code": invitationCode,
		"device_id":       ctx.DeviceConfig.DeviceID,
		"public_key":      string(publicKeyData),
	}

	url := fmt.Sprintf("%s/projects/%s/join", ctx.ProjectConfig.ServerURL, projectID)
	resp, err := makeAPIRequest(http.MethodPost, url, reqBody)
	if err != nil {
		return err
	}

	var response APIResponse
	if err := handleAPIResponse(resp, &response); err != nil {
		return err
	}

	if !response.Success {
		return fmt.Errorf("invitation acceptance failed")
	}

	// Update local config with the new project ID
	ctx.ProjectConfig.ProjectID = projectID
	if err := config.SaveProjectConfig(ctx.CWD, ctx.ProjectConfig); err != nil {
		return fmt.Errorf("failed to update config: %w", err)
	}

	fmt.Printf("Successfully joined project %s!\n", projectID)
	fmt.Println("You can now push and pull .env files for this project.")

	return nil
}

func runMembers(cmd *cobra.Command, args []string) error {
	ctx, err := loadShareContext()
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/projects/%s/members?device_id=%s", ctx.ProjectConfig.ServerURL, ctx.ProjectConfig.ProjectID, ctx.DeviceConfig.DeviceID)
	resp, err := makeAPIRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	var response struct {
		Success bool         `json:"success"`
		Members []MemberInfo `json:"members"`
	}
	if err := handleAPIResponse(resp, &response); err != nil {
		return err
	}

	if !response.Success {
		return fmt.Errorf("failed to get members")
	}

	fmt.Printf("Project Members (%s):\n", ctx.ProjectConfig.ProjectID)
	fmt.Println("====================")

	for _, member := range response.Members {
		roleIndicator := ""
		if member.Role == "owner" {
			roleIndicator = " (Owner)"
		}
		fmt.Printf("- %s%s - Added: %s\n", member.DeviceID, roleIndicator, member.AddedAt.Format("2006-01-02 15:04:05"))
	}

	return nil
}

func runRevoke(cmd *cobra.Command, args []string) error {
	targetDeviceID := args[0]

	ctx, err := loadShareContext()
	if err != nil {
		return err
	}

	reqBody := map[string]string{
		"requester_device_id": ctx.DeviceConfig.DeviceID,
	}

	url := fmt.Sprintf("%s/projects/%s/members/%s", ctx.ProjectConfig.ServerURL, ctx.ProjectConfig.ProjectID, targetDeviceID)
	resp, err := makeAPIRequest(http.MethodDelete, url, reqBody)
	if err != nil {
		return err
	}

	var response APIResponse
	if err := handleAPIResponse(resp, &response); err != nil {
		return err
	}

	if !response.Success {
		return fmt.Errorf("revocation failed")
	}

	fmt.Printf("Successfully removed %s from project %s\n", targetDeviceID, ctx.ProjectConfig.ProjectID)

	return nil
}

// getProjectIDFromInvitation queries the server to get project info from invitation code
func getProjectIDFromInvitation(serverURL, invitationCode string) (string, error) {
	url := fmt.Sprintf("%s/invitations/%s", serverURL, invitationCode)
	resp, err := makeAPIRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	var response struct {
		Success   bool   `json:"success"`
		Message   string `json:"message"`
		ProjectID string `json:"project_id"`
	}
	if err := handleAPIResponse(resp, &response); err != nil {
		return "", err
	}

	if !response.Success {
		return "", fmt.Errorf("invitation validation failed: %s", response.Message)
	}

	return response.ProjectID, nil
}
