package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/nooman57554/The_Orb/orb_libs/authorization"
)

var (
	ErrUnauthorized = errors.New("unauthorized: missing or invalid principal")
	ErrForbidden    = errors.New("forbidden: insufficient permissions")
)

// AuthorizationService coordinates authorization requests using the shared authorization Engine.
type AuthorizationService struct {
	engine authorization.Engine
}

// NewAuthorizationService creates a new AuthorizationService backed by an authorization Engine.
func NewAuthorizationService(engine authorization.Engine) (*AuthorizationService, error) {
	if engine == nil {
		return nil, fmt.Errorf("authorization engine is required")
	}
	return &AuthorizationService{engine: engine}, nil
}

// Authorize evaluates an authorization request using the shared authorization engine.
func (s *AuthorizationService) Authorize(
	ctx context.Context,
	req authorization.AuthorizationRequest,
) (authorization.Decision, error) {
	return s.engine.Authorize(ctx, req)
}

// Engine returns the underlying authorization engine.
func (s *AuthorizationService) Engine() authorization.Engine {
	return s.engine
}
