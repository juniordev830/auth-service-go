package main

import (
	"errors"
	"fmt"
	"time"
)

type TokenClaim struct {
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

func GenerateToken(userID string, role string) (TokenClaim, error) {
	if userID == "" {
		return TokenClaim{}, errors.New("userID cannot be empty")
	}

	return TokenClaim{
		UserID:    userID,
		Role:      role,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}, nil
}

func ValidateToken(claim TokenClaim) bool {
	if claim.UserID == "" {
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
