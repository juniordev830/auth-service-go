package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
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


func TestSignedJWTRoundTrip(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	token, err := GenerateJWT(" usr_123 ", " ADMIN ", secret)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}
	claim, err := VerifyJWT(token, secret)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	if claim.UserID != "usr_123" || claim.Role != "admin" || time.Until(claim.ExpiresAt) <= 0 {
		t.Fatalf("unexpected verified claims: %#v", claim)
	}
}

func TestSignedJWTRejectsTampering(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	token, err := GenerateJWT("usr_123", "user", secret)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"attacker","role":"admin","exp":9999999999,"iat":1,"iss":"auth-service-go","aud":"portfolio-api"}`))
	if _, err := VerifyJWT(strings.Join(parts, "."), secret); err == nil {
		t.Fatal("expected tampered token to be rejected")
	}
}

func TestSignedJWTRequiresStrongSecret(t *testing.T) {
	if _, err := GenerateJWT("usr_123", "user", "short"); err == nil {
		t.Fatal("expected short secret to be rejected")
	}
}


func TestVerifyJWTRejectsOversizedToken(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	token := strings.Repeat("a", maximumTokenBytes+1)
	if _, err := VerifyJWT(token, secret); err == nil {
		t.Fatal("expected oversized JWT to be rejected")
	}
}


func TestSignedJWTRejectsWrongSecret(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	token, err := GenerateJWT("usr_123", "user", secret)
	if err != nil { t.Fatal(err) }
	if _, err := VerifyJWT(token, "abcdef0123456789abcdef0123456789"); err == nil {
		t.Fatal("expected token signed with another secret to be rejected")
	}
}

func TestSignedJWTRejectsFutureIssuedAt(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	token, err := GenerateJWT("usr_123", "user", secret)
	if err != nil { t.Fatal(err) }
	parts := strings.Split(token, ".")
	payload := `{"sub":"usr_123","role":"user","exp":4102444800,"iat":4102444740,"iss":"auth-service-go","aud":"portfolio-api"}`
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(payload))
	unsigned := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(unsigned))
	parts[2] = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if _, err := VerifyJWT(strings.Join(parts, "."), secret); err == nil {
		t.Fatal("expected JWT with future iat to be rejected")
	}
}

func TestGenerateTokenRejectsOversizedUserID(t *testing.T) {
	userID := strings.Repeat("u", maximumUserIDBytes+1)
	if _, err := GenerateToken(userID, "user"); err == nil {
		t.Fatal("expected oversized user ID to be rejected")
	}
}

func TestGenerateTokenAcceptsMaximumUserIDLength(t *testing.T) {
	userID := strings.Repeat("u", maximumUserIDBytes)
	claim, err := GenerateToken(userID, "user")
	if err != nil {
		t.Fatalf("unexpected error for maximum-sized user ID: %v", err)
	}
	if claim.UserID != userID {
		t.Fatal("user ID changed unexpectedly")
	}
}

func TestVerifyJWTRejectsOversizedSubject(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	token, err := GenerateJWT("usr_123", "user", secret)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	payload := `{"sub":"` + strings.Repeat("u", maximumUserIDBytes+1) + `","role":"user","exp":4102444800,"iat":1,"iss":"auth-service-go","aud":"portfolio-api"}`
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(payload))
	unsigned := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(unsigned))
	parts[2] = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if _, err := VerifyJWT(strings.Join(parts, "."), secret); err == nil {
		t.Fatal("expected JWT with oversized subject to be rejected")
	}
}
