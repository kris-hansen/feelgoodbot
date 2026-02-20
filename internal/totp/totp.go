// Package totp provides TOTP-based step-up authentication for sensitive actions
package totp

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

const (
	// Issuer is the name shown in authenticator apps
	Issuer = "Feelgoodbot"
	// SecretSize is the size of the TOTP secret in bytes
	SecretSize = 20
	// BackupCodeCount is the number of backup codes to generate
	BackupCodeCount = 8
	// BackupCodeLength is the length of each backup code
	BackupCodeLength = 8
)

// Store handles persistence of TOTP secrets and backup codes
type Store struct {
	configDir string
}

// TOTPData holds the encrypted TOTP configuration
type TOTPData struct {
	Secret      string    `json:"secret"`
	AccountName string    `json:"account_name"`
	CreatedAt   time.Time `json:"created_at"`
	BackupCodes []string  `json:"backup_codes"`
	UsedBackups []string  `json:"used_backups"`
}

// NewStore creates a new TOTP store
func NewStore() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	configDir := filepath.Join(home, ".config", "feelgoodbot")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	return &Store{configDir: configDir}, nil
}

// IsInitialized returns true if TOTP is already set up
func (s *Store) IsInitialized() bool {
	path := filepath.Join(s.configDir, "totp.json")
	_, err := os.Stat(path)
	return err == nil
}

// Initialize sets up TOTP with a new secret
func (s *Store) Initialize(accountName string) (*TOTPData, string, error) {
	if s.IsInitialized() {
		return nil, "", fmt.Errorf("TOTP already initialized. Use 'feelgoodbot totp reset' to reinitialize")
	}

	// Generate random secret
	secretBytes := make([]byte, SecretSize)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, "", fmt.Errorf("failed to generate secret: %w", err)
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)

	// Generate backup codes
	backupCodes := make([]string, BackupCodeCount)
	for i := 0; i < BackupCodeCount; i++ {
		code, err := generateBackupCode()
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate backup code: %w", err)
		}
		backupCodes[i] = code
	}

	// Create TOTP data
	data := &TOTPData{
		Secret:      secret,
		AccountName: accountName,
		CreatedAt:   time.Now(),
		BackupCodes: backupCodes,
		UsedBackups: []string{},
	}

	// Save to file
	if err := s.save(data); err != nil {
		return nil, "", err
	}

	// Generate QR code
	uri := s.generateOTPAuthURI(secret, accountName)

	return data, uri, nil
}

// generateOTPAuthURI creates the otpauth:// URI for QR codes
func (s *Store) generateOTPAuthURI(secret, accountName string) string {
	// Build the URI manually since we already have the base32 secret
	// Format: otpauth://totp/ISSUER:ACCOUNT?secret=SECRET&issuer=ISSUER&algorithm=SHA1&digits=6&period=30
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		Issuer, accountName, secret, Issuer)
}

// GenerateQRCode creates a QR code image for the TOTP URI
func GenerateQRCode(uri string) (string, error) {
	// Generate QR code as ASCII art for terminal display
	qr, err := qrcode.New(uri, qrcode.Medium)
	if err != nil {
		return "", fmt.Errorf("failed to generate QR code: %w", err)
	}
	return qr.ToSmallString(false), nil
}

// Load reads the TOTP data from disk
func (s *Store) Load() (*TOTPData, error) {
	path := filepath.Join(s.configDir, "totp.json")

	fileData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read TOTP data: %w", err)
	}

	var data TOTPData
	if err := json.Unmarshal(fileData, &data); err != nil {
		return nil, fmt.Errorf("failed to parse TOTP data: %w", err)
	}

	return &data, nil
}

// save writes the TOTP data to disk
func (s *Store) save(data *TOTPData) error {
	path := filepath.Join(s.configDir, "totp.json")

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize TOTP data: %w", err)
	}

	// Write with restrictive permissions
	if err := os.WriteFile(path, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write TOTP data: %w", err)
	}

	return nil
}

// Validate checks if the provided code is valid
func (s *Store) Validate(code string) (bool, error) {
	data, err := s.Load()
	if err != nil {
		return false, err
	}

	// Clean up the code (remove spaces/dashes)
	code = strings.ReplaceAll(code, " ", "")
	code = strings.ReplaceAll(code, "-", "")

	// Check TOTP code first
	valid := totp.Validate(code, data.Secret)
	if valid {
		return true, nil
	}

	// Check backup codes
	for i, backup := range data.BackupCodes {
		if strings.EqualFold(code, backup) {
			// Mark backup code as used
			data.UsedBackups = append(data.UsedBackups, backup)
			data.BackupCodes = append(data.BackupCodes[:i], data.BackupCodes[i+1:]...)
			if err := s.save(data); err != nil {
				return false, fmt.Errorf("failed to update backup codes: %w", err)
			}
			return true, nil
		}
	}

	return false, nil
}

// Reset removes the TOTP configuration
func (s *Store) Reset() error {
	path := filepath.Join(s.configDir, "totp.json")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove TOTP data: %w", err)
	}

	// Also clear session
	sessionPath := filepath.Join(s.configDir, "totp-session")
	_ = os.Remove(sessionPath)

	return nil
}

// GetBackupCodes returns the remaining backup codes
func (s *Store) GetBackupCodes() ([]string, error) {
	data, err := s.Load()
	if err != nil {
		return nil, err
	}
	return data.BackupCodes, nil
}

// RegenerateBackupCodes creates new backup codes
func (s *Store) RegenerateBackupCodes() ([]string, error) {
	data, err := s.Load()
	if err != nil {
		return nil, err
	}

	// Generate new backup codes
	backupCodes := make([]string, BackupCodeCount)
	for i := 0; i < BackupCodeCount; i++ {
		code, err := generateBackupCode()
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}
		backupCodes[i] = code
	}

	data.BackupCodes = backupCodes
	data.UsedBackups = []string{}

	if err := s.save(data); err != nil {
		return nil, err
	}

	return backupCodes, nil
}

// generateBackupCode creates a random backup code
func generateBackupCode() (string, error) {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Excluding confusing chars
	code := make([]byte, BackupCodeLength)
	for i := range code {
		b := make([]byte, 1)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		code[i] = charset[int(b[0])%len(charset)]
	}
	// Format as XXXX-XXXX
	return string(code[:4]) + "-" + string(code[4:]), nil
}

// GenerateCurrentCode generates the current TOTP code (for testing)
func (s *Store) GenerateCurrentCode() (string, error) {
	data, err := s.Load()
	if err != nil {
		return "", err
	}

	code, err := totp.GenerateCode(data.Secret, time.Now())
	if err != nil {
		return "", fmt.Errorf("failed to generate code: %w", err)
	}

	return code, nil
}
