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

func TestGenerateTokenRejectsWhitespaceUser(t *testing.T) {
    if _, err := GenerateToken("   ", "user"); err == nil {
        t.Fatal("expected whitespace-only user ID to be rejected")
    }
}

func TestGenerateTokenRejectsUnknownRole(t *testing.T) {
    if _, err := GenerateToken("usr_123", "superadmin"); err == nil {
        t.Fatal("expected unsupported role to be rejected")
    }
}

func TestGenerateTokenNormalizesUserAndRole(t *testing.T) {
    token, err := GenerateToken(" usr_123 ", " ADMIN ")
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if token.UserID != "usr_123" || token.Role != "admin" {
        t.Fatalf("unexpected normalized claims: %#v", token)
    }
}

func TestValidateTokenRejectsUnknownRole(t *testing.T) {
    token := TokenClaim{UserID: "usr_123", Role: "root", ExpiresAt: time.Now().Add(time.Hour)}
    if ValidateToken(token) {
        t.Fatal("expected unsupported role to be invalid")
    }
}
