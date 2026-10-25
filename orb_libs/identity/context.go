package identity

import (
	"context"
)

type contextKey struct{}

var principalContextKey = contextKey{}

// WithPrincipal places a validated principal into the request context.
//
// Security notice:
// The context value must originate from a trusted authentication boundary (such as
// an authenticating middleware or secure internal transport). Handlers must never
// accept raw client-supplied headers or unverified context values as proof of identity.
func WithPrincipal(ctx context.Context, principal *Principal) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, principalContextKey, principal)
}

// PrincipalFromContext safely retrieves the authenticated principal from context.
//
// It returns the principal and true only if the context contains a non-nil principal
// with valid, non-zero required identifiers (UserID, SessionID, TokenID). Otherwise,
// it returns nil and false.
//
// Security notice:
// Context presence alone is not proof that an arbitrary external caller is authenticated;
// the value must have been placed into the context by a verified authentication boundary.
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	if ctx == nil {
		return nil, false
	}

	principal, ok := ctx.Value(principalContextKey).(*Principal)
	if !ok || principal == nil || !principal.IsValid() {
		return nil, false
	}

	return principal, true
}
