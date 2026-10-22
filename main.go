package main

import (
	"fmt"
	"time"
)

type TokenClaim struct {
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

func GenerateToken(userID string, role string) TokenClaim {
	return TokenClaim{
		UserID:    userID,
		Role:      role,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
}

func main() {
	token := GenerateToken("usr_1001", "admin")
	fmt.Printf("Auth Service Go - Generated Token for User: %s (Role: %s)\n", token.UserID, token.Role)
}
