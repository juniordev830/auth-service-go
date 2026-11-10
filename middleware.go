package main

import (
	"context"
	"errors"
	"net/http"
)

// verifiedClaimKey is private so callers cannot inject an arbitrary claim via
// a string context key. Only the middleware should populate this value.
type verifiedClaimKey struct{}

// VerifiedClaim returns a JWT claim previously verified by the middleware.
// A false result means authentication was not performed on this request.
func VerifiedClaim(ctx context.Context) (TokenClaim, bool) {
	claim, ok := ctx.Value(verifiedClaimKey{}).(TokenClaim)
	return claim, ok
}

// NewBearerMiddleware protects an HTTP handler with HS256 Bearer verification.
//
// By default, any valid user/admin role is accepted. Supplying role names
// restricts access to exactly those roles. Configuration is validated eagerly.
// Invalid or missing credentials return 401, while valid but unauthorized
// roles return 403. No token or secret is written to the HTTP response.
func NewBearerMiddleware(secret string, allowedRoles ...string) (func(http.Handler) http.Handler, error) {
	if err := validateSecret(secret); err != nil {
		return nil, err
	}
	allowed := make(map[string]struct{}, len(allowedRoles))
	for _, role := range allowedRoles {
		if role != "user" && role != "admin" {
			return nil, errors.New("allowed roles must be user or admin")
		}
		if _, duplicated := allowed[role]; duplicated {
			return nil, errors.New("duplicate allowed role")
		}
		allowed[role] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claim, err := VerifyAuthorizationRequest(r, secret)
			if err != nil {
				writeUnauthorized(w)
				return
			}
			if len(allowed) > 0 {
				if _, ok := allowed[claim.Role]; !ok {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
			}
			ctx := context.WithValue(r.Context(), verifiedClaimKey{}, claim)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}, nil
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="portfolio-api"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

