package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/julienschmidt/httprouter"
	_ "github.com/lib/pq"
)

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// createTables creates all necessary database tables
func createTables(db *sql.DB) error {
	schema := `
-- Devices table (global registry of all devices)
CREATE TABLE IF NOT EXISTS devices (
    id SERIAL PRIMARY KEY,
    device_id TEXT UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Projects table
CREATE TABLE IF NOT EXISTS projects (
    id SERIAL PRIMARY KEY,
    project_id TEXT UNIQUE NOT NULL,
    name TEXT,
    master_key_encrypted TEXT NOT NULL,
    owner_device_id TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Project members (many-to-many relationship)
CREATE TABLE IF NOT EXISTS project_members (
    id SERIAL PRIMARY KEY,
    project_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    encrypted_master_key TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'member')),
    added_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, device_id)
);

-- Encrypted files (project-wide)
CREATE TABLE IF NOT EXISTS encrypted_files (
    id SERIAL PRIMARY KEY,
    project_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    encrypted_data TEXT NOT NULL,
    encrypted_key TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, file_name)
);

-- Invitations table
CREATE TABLE IF NOT EXISTS invitations (
    id SERIAL PRIMARY KEY,
    invitation_code TEXT UNIQUE NOT NULL,
    project_id TEXT NOT NULL,
    inviter_device_id TEXT NOT NULL,
    invitee_email TEXT,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    used_by TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_project_members_project_id ON project_members(project_id);
CREATE INDEX IF NOT EXISTS idx_project_members_device_id ON project_members(device_id);
CREATE INDEX IF NOT EXISTS idx_encrypted_files_project_id ON encrypted_files(project_id);
CREATE INDEX IF NOT EXISTS idx_invitations_code ON invitations(invitation_code);
CREATE INDEX IF NOT EXISTS idx_invitations_expires ON invitations(expires_at);
`
	_, err := db.Exec(schema)
	return err
}

// Server holds the database connection
type Server struct {
	db *sql.DB
}

// NewServer creates a new server instance with DB connection
func NewServer(db *sql.DB) *Server {
	return &Server{
		db: db,
	}
}

// Request/Response types
type PushRequest struct {
	DeviceID      string `json:"device_id"`
	EncryptedData string `json:"encrypted_data"`
	EncryptedKey  string `json:"encrypted_key"`
	FileName      string `json:"file_name"`
}

type PullResponse struct {
	Success bool         `json:"success"`
	Message string       `json:"message"`
	Files   []PulledFile `json:"files,omitempty"`
}

type PulledFile struct {
	FileName      string `json:"file_name"`
	EncryptedData string `json:"encrypted_data"`
	EncryptedKey  string `json:"encrypted_key"`
}

type InvitationRequest struct {
	DeviceID    string `json:"device_id"`
	InviteeEmail string `json:"invitee_email,omitempty"`
}

type InvitationResponse struct {
	Success        bool      `json:"success"`
	InvitationCode string    `json:"invitation_code"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type AcceptInvitationRequest struct {
	InvitationCode string `json:"invitation_code"`
	DeviceID       string `json:"device_id"`
	PublicKey      string `json:"public_key"`
}

type AcceptInvitationResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	ProjectID string `json:"project_id"`
}

type MembersResponse struct {
	Success bool        `json:"success"`
	Members []MemberInfo `json:"members"`
}

type MemberInfo struct {
	DeviceID  string    `json:"device_id"`
	Role      string    `json:"role"`
	AddedAt   time.Time `json:"added_at"`
	PublicKey string    `json:"public_key"`
}

type CreateProjectRequest struct {
	ProjectID   string `json:"project_id"`
	DeviceID    string `json:"device_id"`
	PublicKey   string `json:"public_key"`
	ProjectName string `json:"project_name,omitempty"`
}

type CreateProjectResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	ProjectID string `json:"project_id"`
}

type APIResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type RemoveMemberRequest struct {
	RequesterDeviceID string `json:"requester_device_id"`
}

type MasterKeyResponse struct {
	Success            bool   `json:"success"`
	Message            string `json:"message"`
	EncryptedMasterKey string `json:"encrypted_master_key,omitempty"`
}

type InvitationValidationResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	ProjectID string `json:"project_id,omitempty"`
}

// GetMasterKey handles GET /projects/:projectID/master-key
func (s *Server) GetMasterKey(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	projectID := ps.ByName("projectID")
	deviceID := r.URL.Query().Get("device_id")

	// Check if device is member
	if !s.isProjectMember(projectID, deviceID) {
		s.sendError(w, "Access denied", http.StatusForbidden)
		return
	}

	var encryptedMasterKey string
	err := s.db.QueryRow(`
		SELECT encrypted_master_key FROM project_members 
		WHERE project_id = $1 AND device_id = $2`,
		projectID, deviceID).Scan(&encryptedMasterKey)
	if err != nil {
		log.Printf("DB error: %v", err)
		s.sendError(w, "Database error", http.StatusInternalServerError)
		return
	}

	response := MasterKeyResponse{
		Success:            true,
		Message:            "Master key retrieved",
		EncryptedMasterKey: encryptedMasterKey,
	}
	s.sendJSON(w, response)
}

// ValidateInvitation handles GET /invitations/:code
func (s *Server) ValidateInvitation(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	invitationCode := ps.ByName("code")

	var projectID string
	var expiresAt time.Time
	err := s.db.QueryRow(`
		SELECT project_id, expires_at 
		FROM invitations 
		WHERE invitation_code = $1 AND used_at IS NULL AND expires_at > NOW()`,
		invitationCode).Scan(&projectID, &expiresAt)

	if err != nil {
		s.sendError(w, "Invalid or expired invitation", http.StatusBadRequest)
		return
	}

	response := InvitationValidationResponse{
		Success:   true,
		Message:   "Invitation is valid",
		ProjectID: projectID,
	}
	s.sendJSON(w, response)
}

// CreateProject handles POST /projects
func (s *Server) CreateProject(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req CreateProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Register device if not exists
	if err := s.registerDevice(req.DeviceID, req.PublicKey); err != nil {
		log.Printf("DB error registering device: %v", err)
		s.sendError(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Generate a proper AES master key (32 bytes)
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		log.Printf("Error generating master key: %v", err)
		s.sendError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	masterKeyB64 := base64.StdEncoding.EncodeToString(masterKey)

	// Create project
	if err := s.createProject(req.ProjectID, req.DeviceID, masterKeyB64, req.ProjectName); err != nil {
		log.Printf("DB error creating project: %v", err)
		s.sendError(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Add creator as owner
	if err := s.addProjectOwner(req.ProjectID, req.DeviceID, masterKeyB64); err != nil {
		log.Printf("DB error adding owner: %v", err)
		s.sendError(w, "Database error", http.StatusInternalServerError)
		return
	}

	response := CreateProjectResponse{
		Success:   true,
		Message:   "Project created successfully",
		ProjectID: req.ProjectID,
	}
	s.sendJSON(w, response)
}

// Helper methods for common operations

// sendError sends a JSON error response
func (s *Server) sendError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(APIResponse{Success: false, Message: message})
}

// sendJSON sends a JSON response
func (s *Server) sendJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// isProjectMember checks if a device is a member of a project
func (s *Server) isProjectMember(projectID, deviceID string) bool {
	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM project_members 
		WHERE project_id = $1 AND device_id = $2`,
		projectID, deviceID).Scan(&count)
	return err == nil && count > 0
}

// upsertEncryptedFile inserts or updates an encrypted file
func (s *Server) upsertEncryptedFile(projectID string, req PushRequest) error {
	_, err := s.db.Exec(`
		INSERT INTO encrypted_files (project_id, device_id, file_name, encrypted_data, encrypted_key, timestamp)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (project_id, file_name) 
		DO UPDATE SET 
			encrypted_data = EXCLUDED.encrypted_data,
			encrypted_key = EXCLUDED.encrypted_key,
			device_id = EXCLUDED.device_id,
			timestamp = NOW()`,
		projectID, req.DeviceID, req.FileName, req.EncryptedData, req.EncryptedKey)
	return err
}

// getProjectFiles retrieves all files for a project
func (s *Server) getProjectFiles(projectID string) ([]PulledFile, error) {
	rows, err := s.db.Query(`
		SELECT file_name, encrypted_data, encrypted_key
		FROM encrypted_files
		WHERE project_id = $1`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []PulledFile
	for rows.Next() {
		var file PulledFile
		err := rows.Scan(&file.FileName, &file.EncryptedData, &file.EncryptedKey)
		if err != nil {
			continue
		}
		files = append(files, file)
	}
	return files, nil
}

// isProjectOwner checks if a device is the owner of a project
func (s *Server) isProjectOwner(projectID, deviceID string) bool {
	var role string
	err := s.db.QueryRow(`
		SELECT role FROM project_members 
		WHERE project_id = $1 AND device_id = $2`,
		projectID, deviceID).Scan(&role)
	return err == nil && role == "owner"
}

// createInvitation creates a new invitation in the database
func (s *Server) createInvitation(projectID, invitationCode, inviterDeviceID, inviteeEmail string, expiresAt time.Time) error {
	_, err := s.db.Exec(`
		INSERT INTO invitations (invitation_code, project_id, inviter_device_id, invitee_email, expires_at)
		VALUES ($1, $2, $3, $4, $5)`,
		invitationCode, projectID, inviterDeviceID, inviteeEmail, expiresAt)
	return err
}

// verifyInvitation verifies an invitation code and returns the inviter device ID
func (s *Server) verifyInvitation(invitationCode, expectedProjectID string) (string, error) {
	var dbProjectID, inviterDeviceID string
	var expiresAt time.Time
	err := s.db.QueryRow(`
		SELECT project_id, inviter_device_id, expires_at 
		FROM invitations 
		WHERE invitation_code = $1 AND used_at IS NULL AND expires_at > NOW()`,
		invitationCode).Scan(&dbProjectID, &inviterDeviceID, &expiresAt)

	if err != nil {
		return "", fmt.Errorf("invalid or expired invitation")
	}

	if dbProjectID != expectedProjectID {
		return "", fmt.Errorf("invitation code does not match project")
	}

	return inviterDeviceID, nil
}

// registerDevice registers a new device if it doesn't exist
func (s *Server) registerDevice(deviceID, publicKey string) error {
	_, err := s.db.Exec(`
		INSERT INTO devices (device_id, public_key) 
		VALUES ($1, $2) 
		ON CONFLICT (device_id) DO NOTHING`,
		deviceID, publicKey)
	return err
}

// addProjectMember adds a new member to a project
func (s *Server) addProjectMember(projectID, deviceID, inviterDeviceID string) error {
	// Get the inviter's (owner's) encrypted master key
	var ownerEncryptedMasterKey string
	err := s.db.QueryRow(`
		SELECT encrypted_master_key FROM project_members 
		WHERE project_id = $1 AND device_id = $2`,
		projectID, inviterDeviceID).Scan(&ownerEncryptedMasterKey)
	if err != nil {
		return err
	}

	// For now, just use the same encrypted master key
	// In a proper implementation, the client would handle re-encryption
	// The server would need the owner's private key to decrypt and re-encrypt
	encryptedMasterKey := ownerEncryptedMasterKey // Placeholder

	_, err = s.db.Exec(`
		INSERT INTO project_members (project_id, device_id, encrypted_master_key, role)
		VALUES ($1, $2, $3, 'member')`,
		projectID, deviceID, encryptedMasterKey)
	return err
}

// markInvitationUsed marks an invitation as used
func (s *Server) markInvitationUsed(invitationCode, usedBy string) {
	s.db.Exec(`
		UPDATE invitations 
		SET used_at = NOW(), used_by = $1 
		WHERE invitation_code = $2`,
		usedBy, invitationCode)
	// Ignore errors for this operation
}

// getProjectMembers retrieves all members of a project
func (s *Server) getProjectMembers(projectID string) ([]MemberInfo, error) {
	rows, err := s.db.Query(`
		SELECT pm.device_id, pm.role, pm.added_at, d.public_key
		FROM project_members pm
		JOIN devices d ON pm.device_id = d.device_id
		WHERE pm.project_id = $1
		ORDER BY pm.added_at`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []MemberInfo
	for rows.Next() {
		var member MemberInfo
		err := rows.Scan(&member.DeviceID, &member.Role, &member.AddedAt, &member.PublicKey)
		if err != nil {
			continue
		}
		members = append(members, member)
	}
	return members, nil
}

// removeProjectMember removes a member from a project
func (s *Server) removeProjectMember(projectID, deviceID string) error {
	result, err := s.db.Exec(`
		DELETE FROM project_members 
		WHERE project_id = $1 AND device_id = $2`,
		projectID, deviceID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("member not found")
	}

	return nil
}

// createProject creates a new project in the database
func (s *Server) createProject(projectID, ownerDeviceID, masterKey, projectName string) error {
	_, err := s.db.Exec(`
		INSERT INTO projects (project_id, name, master_key_encrypted, owner_device_id)
		VALUES ($1, $2, $3, $4)`,
		projectID, projectName, masterKey, ownerDeviceID)
	return err
}

// addProjectOwner adds the project creator as the owner
func (s *Server) addProjectOwner(projectID, deviceID, masterKey string) error {
	_, err := s.db.Exec(`
		INSERT INTO project_members (project_id, device_id, encrypted_master_key, role)
		VALUES ($1, $2, $3, 'owner')`,
		projectID, deviceID, masterKey)
	return err
}

// PushEnv handles POST /projects/:projectID/env
func (s *Server) PushEnv(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if r.Method != http.MethodPost {
		s.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	projectID := ps.ByName("projectID")
	if projectID == "" {
		s.sendError(w, "Project ID required", http.StatusBadRequest)
		return
	}

	var req PushRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Check if device is member of project
	if !s.isProjectMember(projectID, req.DeviceID) {
		s.sendError(w, "Access denied: not a member of this project", http.StatusForbidden)
		return
	}

	// Insert or update file
	if err := s.upsertEncryptedFile(projectID, req); err != nil {
		log.Printf("DB error: %v", err)
		s.sendError(w, "Database error", http.StatusInternalServerError)
		return
	}

	s.sendJSON(w, APIResponse{Success: true, Message: "File uploaded successfully"})
}

// PullEnv handles GET /projects/:projectID/env
func (s *Server) PullEnv(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if r.Method != http.MethodGet {
		s.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	projectID := ps.ByName("projectID")
	if projectID == "" {
		s.sendError(w, "Project ID required", http.StatusBadRequest)
		return
	}

	deviceID := r.URL.Query().Get("device_id")
	if deviceID == "" {
		s.sendError(w, "Device ID required", http.StatusBadRequest)
		return
	}

	// Check if device is member of project
	if !s.isProjectMember(projectID, deviceID) {
		s.sendError(w, "Access denied: not a member of this project", http.StatusForbidden)
		return
	}

	files, err := s.getProjectFiles(projectID)
	if err != nil {
		log.Printf("DB error: %v", err)
		s.sendError(w, "Database error", http.StatusInternalServerError)
		return
	}

	s.sendJSON(w, PullResponse{Success: true, Message: "Files retrieved successfully", Files: files})
}

// CreateInvitation handles POST /projects/:projectID/invite
func (s *Server) CreateInvitation(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	projectID := ps.ByName("projectID")

	var req InvitationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Check if device is owner
	if !s.isProjectOwner(projectID, req.DeviceID) {
		s.sendError(w, "Access denied: only project owner can create invitations", http.StatusForbidden)
		return
	}

	invitationCode := generateInvitationCode()
	expiresAt := time.Now().Add(7 * 24 * time.Hour) // 7 days

	if err := s.createInvitation(projectID, invitationCode, req.DeviceID, req.InviteeEmail, expiresAt); err != nil {
		log.Printf("DB error creating invitation: %v", err)
		s.sendError(w, "Database error", http.StatusInternalServerError)
		return
	}

	response := InvitationResponse{
		Success:        true,
		InvitationCode: invitationCode,
		ExpiresAt:      expiresAt,
	}
	s.sendJSON(w, response)
}

// AcceptInvitation handles POST /projects/:projectID/join
func (s *Server) AcceptInvitation(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	projectID := ps.ByName("projectID")

	var req AcceptInvitationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Verify invitation
	inviterDeviceID, err := s.verifyInvitation(req.InvitationCode, projectID)
	if err != nil {
		s.sendError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Register device if not exists
	if err := s.registerDevice(req.DeviceID, req.PublicKey); err != nil {
		log.Printf("DB error registering device: %v", err)
		s.sendError(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Get project master key and add member
	if err := s.addProjectMember(projectID, req.DeviceID, inviterDeviceID); err != nil {
		log.Printf("DB error adding member: %v", err)
		s.sendError(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Mark invitation as used
	s.markInvitationUsed(req.InvitationCode, req.DeviceID)

	response := AcceptInvitationResponse{
		Success:   true,
		Message:   "Successfully joined project",
		ProjectID: projectID,
	}
	s.sendJSON(w, response)
}

// ListMembers handles GET /projects/:projectID/members
func (s *Server) ListMembers(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	projectID := ps.ByName("projectID")
	deviceID := r.URL.Query().Get("device_id")

	// Check if requester is member
	if !s.isProjectMember(projectID, deviceID) {
		s.sendError(w, "Access denied", http.StatusForbidden)
		return
	}

	members, err := s.getProjectMembers(projectID)
	if err != nil {
		log.Printf("DB error: %v", err)
		s.sendError(w, "Database error", http.StatusInternalServerError)
		return
	}

	s.sendJSON(w, MembersResponse{Success: true, Members: members})
}

// RemoveMember handles DELETE /projects/:projectID/members/:deviceID
func (s *Server) RemoveMember(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	projectID := ps.ByName("projectID")
	targetDeviceID := ps.ByName("deviceID")

	var req RemoveMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Check if requester is owner
	if !s.isProjectOwner(projectID, req.RequesterDeviceID) {
		s.sendError(w, "Access denied: only project owner can remove members", http.StatusForbidden)
		return
	}

	// Cannot remove yourself
	if req.RequesterDeviceID == targetDeviceID {
		s.sendError(w, "Cannot remove yourself from project", http.StatusBadRequest)
		return
	}

	if err := s.removeProjectMember(projectID, targetDeviceID); err != nil {
		log.Printf("DB error: %v", err)
		s.sendError(w, "Database error", http.StatusInternalServerError)
		return
	}

	s.sendJSON(w, APIResponse{Success: true, Message: "Member removed successfully"})
}

// generateInvitationCode generates a random invitation code
func generateInvitationCode() string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	code := make([]byte, 12)
	charsetLen := big.NewInt(int64(len(charset)))
	for i := range code {
		randomIndex, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			// Fallback to less secure method if crypto/rand fails
			randomIndex = big.NewInt(int64(i % len(charset)))
		}
		code[i] = charset[randomIndex.Int64()]
	}
	return string(code)
}

func main() {
	// Connect to PostgreSQL
	host := getEnv("DB_HOST", "localhost")
	port := getEnv("DB_PORT", "5432")
	user := getEnv("DB_USER", "envsync")
	password := getEnv("DB_PASSWORD", "password")
	dbname := getEnv("DB_NAME", "envsync")

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// Test connection
	if err := db.Ping(); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	// Create tables
	if err := createTables(db); err != nil {
		log.Fatal("Failed to create tables:", err)
	}

	server := NewServer(db)

	router := httprouter.New()
	router.POST("/projects", server.CreateProject)
	router.POST("/projects/:projectID/env", server.PushEnv)
	router.GET("/projects/:projectID/env", server.PullEnv)

	// Share endpoints
	router.GET("/invitations/:code", server.ValidateInvitation)
	router.GET("/projects/:projectID/master-key", server.GetMasterKey)
	router.POST("/projects/:projectID/invite", server.CreateInvitation)
	router.POST("/projects/:projectID/join", server.AcceptInvitation)
	router.GET("/projects/:projectID/members", server.ListMembers)
	router.DELETE("/projects/:projectID/members/:deviceID", server.RemoveMember)

	fmt.Println("EnvSync server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}