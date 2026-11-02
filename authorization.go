package main

import (
    "errors"
    "strings"
)

// VerifyAuthorizationHeader validates a single HTTP Authorization header value
// using the Bearer scheme, then verifies the JWT signature and claims.
// HTTP handlers must reject duplicate Authorization headers separately.
func VerifyAuthorizationHeader(value, secret string) (TokenClaim, error) {
    if len(value) > maximumTokenBytes+32 || strings.ContainsAny(value, "\r\n\t") {
        return TokenClaim{}, errors.New("invalid Authorization header")
    }

    separator := strings.IndexByte(value, ' ')
    if separator <= 0 || !strings.EqualFold(value[:separator], "Bearer") {
        return TokenClaim{}, errors.New("expected Bearer authorization")
    }

    // RFC 6750 allows one or more spaces between Bearer and the credential.
    token := strings.TrimLeft(value[separator+1:], " ")
    if token == "" || strings.ContainsAny(token, " \t\r\n") {
        return TokenClaim{}, errors.New("invalid Bearer credential")
    }
    return VerifyJWT(token, secret)
}
