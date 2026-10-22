package main

import (
	"testing"
	"time"
)

func TestGenerateTokenSuccess(t *testing.T) {
	token, err := GenerateToken("usr_123", "admin")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if token.UserID != "usr_123" {
		t.Errorf("Expected UserID 'usr_123', got '%s'", token.UserID)
	}

	if token.Role != "admin" {
		t.Errorf("Expected Role 'admin', got '%s'", token.Role)
	}
}

func TestGenerateTokenEmptyUser(t *testing.T) {
	_, err := GenerateToken("", "admin")
	if err == nil {
		t.Fatal("Expected error for empty userID, got nil")
	}
}

func TestValidateToken(t *testing.T) {
	validToken := TokenClaim{
		UserID:    "usr_123",
		Role:      "user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	if !ValidateToken(validToken) {
		t.Error("Expected token to be valid")
	}

	expiredToken := TokenClaim{
		UserID:    "usr_123",
		Role:      "user",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	if ValidateToken(expiredToken) {
		t.Error("Expected expired token to be invalid")
	}
}
