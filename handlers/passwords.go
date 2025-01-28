package handlers

import (
	"backend/models"
	"backend/utils"
	"database/sql"
	"encoding/json"
	"net/http"
)

type PasswordHandler struct {
	db *sql.DB
}

func NewPasswordHandler(db *sql.DB) *PasswordHandler {
	return &PasswordHandler{db: db}
}

func (h *PasswordHandler) HandlePasswords(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.GetPasswords(w, r)
	case http.MethodPost:
		h.AddPassword(w, r)
	case http.MethodDelete:
		h.DeletePassword(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *PasswordHandler) GetPasswords(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(int)
	rows, err := h.db.Query("SELECT id, name, username, password FROM passwords WHERE user_id = ?", userID)
	if err != nil {
		http.Error(w, "Failed to fetch passwords", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var passwords []models.Password
	for rows.Next() {
		var p models.Password
		if err := rows.Scan(&p.ID, &p.Name, &p.Username, &p.Password); err != nil {
			http.Error(w, "Failed to read password", http.StatusInternalServerError)
			return
		}
		passwords = append(passwords, p)
	}

	json.NewEncoder(w).Encode(passwords)
}

func (h *PasswordHandler) AddPassword(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(int)
	var p models.Password
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	encryptedPassword, err := utils.Encrypt([]byte("32-byte-long-encryption-key"), p.Password)
	if err != nil {
		http.Error(w, "Failed to encrypt password", http.StatusInternalServerError)
		return
	}

	_, err = h.db.Exec("INSERT INTO passwords (user_id, name, username, password) VALUES (?, ?, ?, ?)", userID, p.Name, p.Username, encryptedPassword)
	if err != nil {
		http.Error(w, "Failed to save password", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (h *PasswordHandler) DeletePassword(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(int)
	var p struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "Invalid  request", http.StatusBadRequest)
		return
	}

	_, err := h.db.Exec("DELETE FROM passwords WHERE id = ? AND user_if = ?", p.ID, userID)
	if err != nil {
		http.Error(w, "Failed to delete password", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
