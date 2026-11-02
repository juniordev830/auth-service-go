package main

import (
    "strings"
    "testing"
)

const bearerTestSecret = "0123456789abcdef0123456789abcdef"

func TestVerifyAuthorizationHeaderAcceptsValidBearerTokens(t *testing.T) {
    jwt, err := GenerateJWT("usr_123", "admin", bearerTestSecret)
    if err != nil {
        t.Fatal(err)
    }
    for _, header := range []string{
        "Bearer " + jwt,
        "bearer " + jwt,
        "BEARER  " + jwt,
    } {
        claim, err := VerifyAuthorizationHeader(header, bearerTestSecret)
        if err != nil {
            t.Fatalf("unexpected rejection for header: %v", err)
        }
        if claim.UserID != "usr_123" || claim.Role != "admin" {
            t.Fatalf("unexpected claims: %#v", claim)
        }
    }
}

func TestVerifyAuthorizationHeaderRejectsMalformedCredentials(t *testing.T) {
    jwt, err := GenerateJWT("usr_123", "user", bearerTestSecret)
    if err != nil {
        t.Fatal(err)
    }
    tests := []struct {
        name string
        value string
    }{
        {"missing header", ""},
        {"missing scheme", jwt},
        {"wrong scheme", "Basic " + jwt},
        {"missing credential", "Bearer "},
        {"leading whitespace", " Bearer " + jwt},
        {"trailing whitespace", "Bearer " + jwt + " "},
        {"extra credential", "Bearer " + jwt + " another"},
        {"tab separator", "Bearer\t" + jwt},
        {"newline injection", "Bearer " + jwt + "\r\nX-Test: injected"},
        {"oversized header", "Bearer " + strings.Repeat("a", maximumTokenBytes+33)},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if _, err := VerifyAuthorizationHeader(tt.value, bearerTestSecret); err == nil {
                t.Fatal("expected malformed Authorization header to be rejected")
            }
        })
    }
}

func TestVerifyAuthorizationHeaderRejectsBadSignature(t *testing.T) {
    jwt, err := GenerateJWT("usr_123", "user", bearerTestSecret)
    if err != nil {
        t.Fatal(err)
    }
    if _, err := VerifyAuthorizationHeader("Bearer "+jwt, "abcdef0123456789abcdef0123456789"); err == nil {
        t.Fatal("expected JWT signed with another secret to be rejected")
    }
}
