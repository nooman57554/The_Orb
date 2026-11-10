package authorization

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
)

var (
	ErrMissingTenantParam = errors.New("missing tenant route parameter")
	ErrInvalidTenantUUID  = errors.New("tenant ID is not a valid UUID")
	ErrNoTenantInContext  = errors.New("no tenant ID found in request context")
)

// TenantResolver resolves the target tenant ID from a trusted source on the request.
// Never resolve tenant ID from an untrusted client header.
type TenantResolver interface {
	ResolveTenant(r *http.Request) (string, error)
}

// RouteParamResolver resolves tenant ID from an http.Request PathValue (e.g. "tenantID" or "id").
type RouteParamResolver string

func (p RouteParamResolver) ResolveTenant(r *http.Request) (string, error) {
	val := strings.TrimSpace(r.PathValue(string(p)))
	if val == "" {
		return "", fmt.Errorf("%w: param %q", ErrMissingTenantParam, string(p))
	}
	parsed, err := uuid.Parse(val)
	if err != nil || parsed == uuid.Nil {
		return "", fmt.Errorf("%w: %q", ErrInvalidTenantUUID, val)
	}
	return parsed.String(), nil
}

// RouteParam returns a TenantResolver that extracts and validates a route parameter.
func RouteParam(paramName string) TenantResolver {
	return RouteParamResolver(paramName)
}

// ContextResolver resolves tenant ID from the authenticated principal in request context.
type ContextResolver struct{}

func (ContextResolver) ResolveTenant(r *http.Request) (string, error) {
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok || principal == nil || !principal.IsValid() {
		return "", ErrNoTenantInContext
	}
	if principal.TenantID == nil || *principal.TenantID == uuid.Nil {
		return "", ErrNoTenantInContext
	}
	return principal.TenantID.String(), nil
}

// FromContext returns a TenantResolver that extracts tenant ID from the verified principal.
func FromContext() TenantResolver {
	return ContextResolver{}
}
