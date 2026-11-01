package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const jwtIssuer = "auth-service-go"
const jwtAudience = "portfolio-api"
const jwtLifetime = 24 * time.Hour
const minimumSecretBytes = 32

type TokenClaim struct {
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type jwtPayload struct {
	Subject   string `json:"sub"`
	Role      string `json:"role"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
}

func validateSecret(secret string) error {
	if len([]byte(secret)) < minimumSecretBytes {
		return errors.New("JWT secret must contain at least 32 bytes")
	}
	return nil
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
	return TokenClaim{UserID: userID, Role: role, ExpiresAt: time.Now().UTC().Add(jwtLifetime)}, nil
}

// GenerateJWT creates a compact HS256 JWT. Callers must supply a secret from a
// secret manager or environment variable; never commit production secrets.
func GenerateJWT(userID, role, secret string) (string, error) {
	if err := validateSecret(secret); err != nil {
		return "", err
	}
	claim, err := GenerateToken(userID, role)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	headerBytes, err := json.Marshal(jwtHeader{Algorithm: "HS256", Type: "JWT"})
	if err != nil {
		return "", err
	}
	payloadBytes, err := json.Marshal(jwtPayload{
		Subject: claim.UserID, Role: claim.Role,
		ExpiresAt: claim.ExpiresAt.Unix(), IssuedAt: now.Unix(),
		Issuer: jwtIssuer, Audience: jwtAudience,
	})
	if err != nil {
		return "", err
	}
	encoder := base64.RawURLEncoding
	unsigned := encoder.EncodeToString(headerBytes) + "." + encoder.EncodeToString(payloadBytes)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(unsigned))
	return unsigned + "." + encoder.EncodeToString(mac.Sum(nil)), nil
}

// VerifyJWT verifies the signature before trusting claims and validates the
// algorithm, issuer, audience, role, subject, issue time, and expiry.
func VerifyJWT(token, secret string) (TokenClaim, error) {
	if err := validateSecret(secret); err != nil {
		return TokenClaim{}, err
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return TokenClaim{}, errors.New("malformed JWT")
	}
	encoder := base64.RawURLEncoding
	headerBytes, err := encoder.DecodeString(parts[0])
	if err != nil {
		return TokenClaim{}, errors.New("malformed JWT header")
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Algorithm != "HS256" || header.Type != "JWT" {
		return TokenClaim{}, errors.New("unsupported JWT header")
	}
	signature, err := encoder.DecodeString(parts[2])
	if err != nil {
		return TokenClaim{}, errors.New("malformed JWT signature")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return TokenClaim{}, errors.New("invalid JWT signature")
	}
	payloadBytes, err := encoder.DecodeString(parts[1])
	if err != nil {
		return TokenClaim{}, errors.New("malformed JWT payload")
	}
	var payload jwtPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return TokenClaim{}, errors.New("malformed JWT payload")
	}
	now := time.Now().UTC().Unix()
	if strings.TrimSpace(payload.Subject) == "" ||
		(payload.Role != "user" && payload.Role != "admin") ||
		payload.Issuer != jwtIssuer || payload.Audience != jwtAudience ||
		payload.ExpiresAt <= now || payload.IssuedAt > now+60 ||
		payload.ExpiresAt <= payload.IssuedAt ||
		payload.ExpiresAt-payload.IssuedAt > int64(jwtLifetime.Seconds())+60 {
		return TokenClaim{}, errors.New("invalid or expired JWT claims")
	}
	return TokenClaim{
		UserID: payload.Subject, Role: payload.Role,
		ExpiresAt: time.Unix(payload.ExpiresAt, 0).UTC(),
	}, nil
}

// ValidateToken validates an in-memory claim only; it does not verify a JWT.
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
	fmt.Println("Auth Service Go: library demo. Use GenerateJWT/VerifyJWT with a strong secret.")
}
