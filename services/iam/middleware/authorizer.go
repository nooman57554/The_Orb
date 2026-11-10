package middleware

import (
	"fmt"

	"github.com/nooman57554/The_Orb/orb_libs/authorization"
)

// Authorizer enforces route authorization policies via the unified authorization engine.
type Authorizer struct {
	*authorization.Authorizer
}

// NewAuthorizer creates a new route-level Authorizer backed by the shared authorization Engine.
func NewAuthorizer(engine authorization.Engine) (*Authorizer, error) {
	if engine == nil {
		return nil, fmt.Errorf("authorization engine is required")
	}
	authz, err := authorization.NewAuthorizer(engine)
	if err != nil {
		return nil, err
	}
	return &Authorizer{Authorizer: authz}, nil
}
