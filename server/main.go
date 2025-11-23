package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
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

// EncryptedFile represents stored encrypted .env data
type EncryptedFile struct {
	DeviceID      string    `json:"device_id"`
	EncryptedData string    `json:"encrypted_data"`
	EncryptedKey  string    `json:"encrypted_key"`
	FileName      string    `json:"file_name"`
	Timestamp     time.Time `json:"timestamp"`
}

// ProjectData holds all files for a project
type ProjectData struct {
	Files map[string]EncryptedFile `json:"files"` // fileName -> file
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

// PushEnv handles POST /projects/:projectID/env
func (s *Server) PushEnv(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	projectID := ps.ByName("projectID")
	if projectID == "" {
		http.Error(w, "Project ID required", http.StatusBadRequest)
		return
	}

	var req struct {
		DeviceID      string `json:"device_id"`
		EncryptedData string `json:"encrypted_data"`
		EncryptedKey  string `json:"encrypted_key"`
		FileName      string `json:"file_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Insert into DB
	_, err := s.db.Exec(`
		INSERT INTO encrypted_files (project_id, device_id, file_name, encrypted_data, encrypted_key, timestamp)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (project_id, file_name) 
		DO UPDATE SET 
			device_id = EXCLUDED.device_id,
			encrypted_data = EXCLUDED.encrypted_data,
			encrypted_key = EXCLUDED.encrypted_key,
			timestamp = EXCLUDED.timestamp`,
		projectID, req.DeviceID, req.FileName, req.EncryptedData, req.EncryptedKey, time.Now())

	if err != nil {
		log.Printf("DB error: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "File uploaded successfully",
	})
}

// PullEnv handles GET /projects/:projectID/env
func (s *Server) PullEnv(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	projectID := ps.ByName("projectID")
	if projectID == "" {
		http.Error(w, "Project ID required", http.StatusBadRequest)
		return
	}

	deviceID := r.URL.Query().Get("device_id")
	if deviceID == "" {
		http.Error(w, "Device ID required", http.StatusBadRequest)
		return
	}

	// Query DB
	rows, err := s.db.Query(`
		SELECT device_id, encrypted_data, encrypted_key, file_name, timestamp
		FROM encrypted_files
		WHERE project_id = $1`, projectID)

	if err != nil {
		log.Printf("DB error: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var files []EncryptedFile
	for rows.Next() {
		var file EncryptedFile
		err := rows.Scan(&file.DeviceID, &file.EncryptedData, &file.EncryptedKey, &file.FileName, &file.Timestamp)
		if err != nil {
			log.Printf("Scan error: %v", err)
			continue
		}
		files = append(files, file)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"files":   files,
	})
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

	// Create table if not exists
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS encrypted_files (
			id SERIAL PRIMARY KEY,
			project_id TEXT NOT NULL,
			device_id TEXT NOT NULL,
			file_name TEXT NOT NULL,
			encrypted_data TEXT NOT NULL,
			encrypted_key TEXT NOT NULL,
			timestamp TIMESTAMP NOT NULL,
			UNIQUE(project_id, file_name)
		)`)
	if err != nil {
		log.Fatal("Failed to create table:", err)
	}

	server := NewServer(db)

	router := httprouter.New()
	router.POST("/projects/:projectID/env", server.PushEnv)
	router.GET("/projects/:projectID/env", server.PullEnv)

	fmt.Println("EnvSync server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}