package main

import (
    "errors"
    "net/http"
    "strings"
)

// VerifyAuthorizationRequest verifies exactly one Authorization header and its JWT.
// Iterating over keys instead of Header.Get rejects duplicate or differently-cased
// header keys, rather than silently accepting just the first credential.
func VerifyAuthorizationRequest(request *http.Request, secret string) (TokenClaim, error) {
    if request == nil {
        return TokenClaim{}, errors.New("request is required")
    }
    var credential string
    count := 0
    for name, values := range request.Header {
        if !strings.EqualFold(name, "Authorization") {
            continue
        }
        count += len(values)
        if count > 1 {
            return TokenClaim{}, errors.New("multiple Authorization values are not allowed")
        }
        if len(values) == 1 {
            credential = values[0]
        }
    }
    if count != 1 {
        return TokenClaim{}, errors.New("exactly one Authorization value is required")
    }
    return VerifyAuthorizationHeader(credential, secret)
}
