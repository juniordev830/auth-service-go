package main

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type TokenClaim struct {
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

func GenerateToken(userID string, role string) (TokenClaim, error) {
	userID = strings.TrimSpace(userID)
	role = strings.ToLower(strings.TrimSpace(role))
	if userID == "" {
		return TokenClaim{}, errors.New("userID cannot be empty")
	}
	if role != "user" && role != "admin" {
		return TokenClaim{}, errors.New("role must be either user or admin")
	}

	return TokenClaim{
		UserID:    userID,
		Role:      role,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}, nil
}

func ValidateToken(claim TokenClaim) bool {
	if strings.TrimSpace(claim.UserID) == "" {
		return false
	}
	role := strings.ToLower(strings.TrimSpace(claim.Role))
	if role != "user" && role != "admin" {
		return false
	}
	return time.Now().Before(claim.ExpiresAt)
}

func main() {
	token, err := GenerateToken("usr_1001", "admin")
	if err != nil {
		fmt.Println("Error generating token:", err)
		return
	}

	valid := ValidateToken(token)
	fmt.Printf("Auth Service Go - Generated Token for User: %s (Role: %s, Valid: %t)\n", token.UserID, token.Role, valid)
}
