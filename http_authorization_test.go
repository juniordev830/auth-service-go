package main

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestVerifyAuthorizationRequestAcceptsSingleValidBearer(t *testing.T) {
    token, err := GenerateJWT("client_123", "user", bearerTestSecret)
    if err != nil { t.Fatal(err) }
    request := httptest.NewRequest("GET", "/private", nil)
    request.Header.Set("Authorization", "Bearer "+token)
    claims, err := VerifyAuthorizationRequest(request, bearerTestSecret)
    if err != nil { t.Fatalf("valid token was rejected: %v", err) }
    if claims.UserID != "client_123" || claims.Role != "user" {
        t.Fatalf("unexpected claims: %#v", claims)
    }
}

func TestVerifyAuthorizationRequestRejectsMissingDuplicateAndMalformedHeaders(t *testing.T) {
    token, err := GenerateJWT("client_123", "admin", bearerTestSecret)
    if err != nil { t.Fatal(err) }
    for name, request := range map[string]func() *http.Request{
        "missing": func() *http.Request {
            return httptest.NewRequest("GET", "/private", nil)
        },
        "duplicate": func() *http.Request {
            r := httptest.NewRequest("GET", "/private", nil)
            r.Header.Add("Authorization", "Bearer "+token)
            r.Header.Add("Authorization", "Bearer "+token)
            return r
        },
        "mixed case duplicates": func() *http.Request {
            r := httptest.NewRequest("GET", "/private", nil)
            r.Header["Authorization"] = []string{"Bearer " + token}
            r.Header["authorization"] = []string{"Bearer " + token}
            return r
        },
        "empty": func() *http.Request {
            r := httptest.NewRequest("GET", "/private", nil)
            r.Header.Set("Authorization", "")
            return r
        },
        "wrong scheme": func() *http.Request {
            r := httptest.NewRequest("GET", "/private", nil)
            r.Header.Set("Authorization", "Basic "+token)
            return r
        },
    } {
        t.Run(name, func(t *testing.T) {
            if _, err := VerifyAuthorizationRequest(request(), bearerTestSecret); err == nil {
                t.Fatal("expected request authorization to fail")
            }
        })
    }
    if _, err := VerifyAuthorizationRequest(nil, bearerTestSecret); err == nil {
        t.Fatal("nil requests must be rejected")
    }
}
