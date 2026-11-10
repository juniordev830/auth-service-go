package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const middlewareTestSecret = "0123456789abcdef0123456789abcdef"

func signedJWT(t *testing.T, userID, role string) string {
	t.Helper()
	token, err := GenerateJWT(userID, role, middlewareTestSecret)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return token
}

func wrapForTest(t *testing.T, roles ...string) http.Handler {
	t.Helper()
	middleware, err := NewBearerMiddleware(middlewareTestSecret, roles...)
	if err != nil {
		t.Fatalf("create middleware: %v", err)
	}
	return middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claim, ok := VerifiedClaim(r.Context())
		if !ok || claim.UserID != "demo-user" {
			t.Fatalf("missing verified user claim: %#v", claim)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}

func serveAuth(t *testing.T, handler http.Handler, values ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	for _, value := range values {
		req.Header.Add("Authorization", value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func TestMiddlewareAllowsValidBearerAndInjectsVerifiedClaim(t *testing.T) {
	token := signedJWT(t, "demo-user", "user")
	response := serveAuth(t, wrapForTest(t, "user"), "Bearer "+token)
	if response.Code != http.StatusNoContent {
		t.Fatalf("expected success, got %d: %s", response.Code, response.Body.String())
	}

	admin := signedJWT(t, "demo-user", "admin")
	if response := serveAuth(t, wrapForTest(t), "Bearer "+admin); response.Code != http.StatusNoContent {
		t.Fatalf("valid admin rejected by role-neutral middleware: %d", response.Code)
	}
}

func TestMiddlewareRejectsMissingDuplicateAndMalformedAuthorization(t *testing.T) {
	token := signedJWT(t, "demo-user", "user")
	handler := wrapForTest(t, "user")
	cases := [][]string{
		nil,
		{"Basic " + token},
		{"Bearer "},
		{"Bearer " + token, "Bearer " + token},
		{"Bearer " + token + " bad"},
		{"Bearer " + token + "\r\nX-Injected: evil"},
	}
	for _, headers := range cases {
		response := serveAuth(t, handler, headers...)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for %d headers, got %d", len(headers), response.Code)
		}
		if response.Header().Get("WWW-Authenticate") != `Bearer realm="portfolio-api"` {
			t.Fatal("missing bearer challenge")
		}
		if strings.Contains(response.Body.String(), middlewareTestSecret) ||
			strings.Contains(response.Body.String(), token) {
			t.Fatal("response leaked token or secret")
		}
	}
}

func TestMiddlewareRejectsTamperedTokenAndWrongSecret(t *testing.T) {
	token := signedJWT(t, "demo-user", "user")
	handler := wrapForTest(t)
	tampered := token[:len(token)-1] + "!"
	if response := serveAuth(t, handler, "Bearer "+tampered); response.Code != http.StatusUnauthorized {
		t.Fatalf("tampered token accepted: %d", response.Code)
	}
	middleware, err := NewBearerMiddleware("another-secret-0123456789abcdef0123456789")
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("token with wrong key must not reach handler")
	}))
	if response := serveAuth(t, wrongKey, "Bearer "+token); response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-secret request got %d", response.Code)
	}
}

func TestMiddlewareRejectsDifferentlyCasedAuthorizationKeys(t *testing.T) {
	token := signedJWT(t, "demo-user", "user")
	request := httptest.NewRequest(http.MethodGet, "/private", nil)
	request.Header["Authorization"] = []string{"Bearer " + token}
	request.Header["authorization"] = []string{"Bearer " + token}
	response := httptest.NewRecorder()
	wrapForTest(t).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate authorization keys must be rejected: got %d", response.Code)
	}
}

func TestMiddlewareReturns403ForValidButUnauthorizedRole(t *testing.T) {
	token := signedJWT(t, "demo-user", "user")
	response := serveAuth(t, wrapForTest(t, "admin"), "Bearer "+token)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", response.Code)
	}
	if strings.Contains(response.Body.String(), token) {
		t.Fatal("forbidden response leaked token")
	}
}

func TestMiddlewareRefusesInvalidConfiguration(t *testing.T) {
	for _, config := range []struct {
		secret string
		roles  []string
	}{
		{"too-short", []string{"admin"}},
		{middlewareTestSecret, []string{"superuser"}},
		{middlewareTestSecret, []string{"user", "user"}},
	} {
		if _, err := NewBearerMiddleware(config.secret, config.roles...); err == nil {
			t.Fatalf("expected invalid configuration rejection: %+v", config)
		}
	}
}

func TestUnauthenticatedContextDoesNotClaimVerification(t *testing.T) {
	if _, ok := VerifiedClaim(context.Background()); ok {
		t.Fatal("empty context must not be considered authenticated")
	}
}

