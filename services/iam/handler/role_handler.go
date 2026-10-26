package handler

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/httpx"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/repository"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

type RoleHandler struct {
	roleService    *service.RoleService
	authzService   *service.AuthorizationService
	roleAssignRepo repository.RoleAssignmentRepository
}

func NewRoleHandler(
	roleService *service.RoleService,
	authzService *service.AuthorizationService,
	roleAssignRepo repository.RoleAssignmentRepository,
) *RoleHandler {
	return &RoleHandler{
		roleService:    roleService,
		authzService:   authzService,
		roleAssignRepo: roleAssignRepo,
	}
}

type rolePermissionResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type roleResponse struct {
	ID          string                   `json:"id"`
	Name        string                   `json:"name"`
	Scope       string                   `json:"scope"`
	TenantID    *string                  `json:"tenant_id,omitempty"`
	Description string                   `json:"description"`
	Permissions []rolePermissionResponse `json:"permissions,omitempty"`
	CreatedAt   string                   `json:"created_at"`
	UpdatedAt   string                   `json:"updated_at"`
}

type createRoleRequest struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	PermissionIDs []string `json:"permission_ids"`
}

type updateRoleRequest struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	PermissionIDs []string `json:"permission_ids"`
}

func formatRole(r *model.Role) roleResponse {
	var tenantID *string
	if r.TenantID != nil && *r.TenantID != uuid.Nil {
		s := r.TenantID.String()
		tenantID = &s
	}

	perms := make([]rolePermissionResponse, len(r.Permissions))
	for i, p := range r.Permissions {
		perms[i] = rolePermissionResponse{
			ID:          p.ID.String(),
			Name:        p.Name,
			Description: p.Description,
		}
	}

	return roleResponse{
		ID:          r.ID.String(),
		Name:        r.Name,
		Scope:       r.Scope,
		TenantID:    tenantID,
		Description: r.Description,
		Permissions: perms,
		CreatedAt:   r.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   r.UpdatedAt.Format(time.RFC3339),
	}
}

func (h *RoleHandler) ListPlatformRoles(w http.ResponseWriter, r *http.Request) {
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok {
		httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
		return
	}

	if err := h.authzService.AuthorizePlatform(r.Context(), principal, "role.read"); err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
			return
		}
		if errors.Is(err, service.ErrForbidden) {
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "You are not authorized to view platform roles.")
			return
		}
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	roles, err := h.roleService.ListPlatformRoles(r.Context())
	if err != nil {
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	items := make([]roleResponse, len(roles))
	for i := range roles {
		items[i] = formatRole(&roles[i])
	}

	writeJSON(w, http.StatusOK, struct {
		Roles []roleResponse `json:"roles"`
	}{Roles: items})
}

func (h *RoleHandler) ListTenantRoles(w http.ResponseWriter, r *http.Request) {
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok {
		httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
		return
	}

	tenantID, err := uuid.Parse(r.PathValue("tenantID"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant ID must be a valid UUID.")
		return
	}

	if err := h.authzService.AuthorizeTenant(r.Context(), principal, tenantID, "role.read"); err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
			return
		}
		if errors.Is(err, service.ErrForbidden) {
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "You are not authorized to view roles in this tenant.")
			return
		}
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	roles, err := h.roleService.ListTenantRoles(r.Context(), tenantID)
	if err != nil {
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	items := make([]roleResponse, len(roles))
	for i := range roles {
		items[i] = formatRole(&roles[i])
	}

	writeJSON(w, http.StatusOK, struct {
		Roles []roleResponse `json:"roles"`
	}{Roles: items})
}

func (h *RoleHandler) GetTenantRole(w http.ResponseWriter, r *http.Request) {
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok {
		httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
		return
	}

	tenantID, err := uuid.Parse(r.PathValue("tenantID"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant ID must be a valid UUID.")
		return
	}
	roleID, err := uuid.Parse(r.PathValue("roleID"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Role ID must be a valid UUID.")
		return
	}

	if err := h.authzService.AuthorizeTenant(r.Context(), principal, tenantID, "role.read"); err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
			return
		}
		if errors.Is(err, service.ErrForbidden) {
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "You are not authorized to view roles in this tenant.")
			return
		}
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	role, err := h.roleService.GetTenantRole(r.Context(), tenantID, roleID)
	if err != nil {
		if errors.Is(err, service.ErrRoleNotFound) {
			httpx.WriteProblem(w, http.StatusNotFound, "Role Not Found", "The requested role was not found.")
			return
		}
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	writeJSON(w, http.StatusOK, formatRole(role))
}

func (h *RoleHandler) CreateCustomTenantRole(w http.ResponseWriter, r *http.Request) {
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok {
		httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
		return
	}

	tenantID, err := uuid.Parse(r.PathValue("tenantID"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant ID must be a valid UUID.")
		return
	}

	if err := h.authzService.AuthorizeTenant(r.Context(), principal, tenantID, "role.create"); err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
			return
		}
		if errors.Is(err, service.ErrForbidden) {
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "You are not authorized to create roles in this tenant.")
			return
		}
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	var req createRoleRequest
	if err := decodeJSON(w, r, &req); err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Request body must contain valid JSON.")
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Role name cannot be empty.")
		return
	}

	permUUIDs := make([]uuid.UUID, 0, len(req.PermissionIDs))
	for _, pid := range req.PermissionIDs {
		u, err := uuid.Parse(strings.TrimSpace(pid))
		if err != nil {
			httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "permission_ids must contain valid UUIDs.")
			return
		}
		permUUIDs = append(permUUIDs, u)
	}

	role, err := h.roleService.CreateCustomTenantRole(r.Context(), tenantID, name, req.Description, permUUIDs)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidRoleName):
			httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Role name cannot be empty.")
		case errors.Is(err, service.ErrPrivilegeEscalation):
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "Cannot grant platform permissions to tenant custom roles.")
		case errors.Is(err, service.ErrInvalidPermissionScope):
			httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "One or more permissions are invalid or unknown.")
		case errors.Is(err, repository.ErrDuplicateRoleName):
			httpx.WriteProblem(w, http.StatusConflict, "Role Already Exists", "A role with this name already exists in this tenant.")
		default:
			httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		}
		return
	}

	writeJSON(w, http.StatusCreated, formatRole(role))
}

func (h *RoleHandler) UpdateCustomTenantRole(w http.ResponseWriter, r *http.Request) {
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok {
		httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
		return
	}

	tenantID, err := uuid.Parse(r.PathValue("tenantID"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant ID must be a valid UUID.")
		return
	}
	roleID, err := uuid.Parse(r.PathValue("roleID"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Role ID must be a valid UUID.")
		return
	}

	if err := h.authzService.AuthorizeTenant(r.Context(), principal, tenantID, "role.update"); err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
			return
		}
		if errors.Is(err, service.ErrForbidden) {
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "You are not authorized to update roles in this tenant.")
			return
		}
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	var req updateRoleRequest
	if err := decodeJSON(w, r, &req); err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Request body must contain valid JSON.")
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Role name cannot be empty.")
		return
	}

	var permUUIDs []uuid.UUID
	if req.PermissionIDs != nil {
		permUUIDs = make([]uuid.UUID, 0, len(req.PermissionIDs))
		for _, pid := range req.PermissionIDs {
			u, err := uuid.Parse(strings.TrimSpace(pid))
			if err != nil {
				httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "permission_ids must contain valid UUIDs.")
				return
			}
			permUUIDs = append(permUUIDs, u)
		}
	}

	role, err := h.roleService.UpdateCustomTenantRole(r.Context(), tenantID, roleID, name, req.Description, permUUIDs)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrRoleNotFound):
			httpx.WriteProblem(w, http.StatusNotFound, "Role Not Found", "The requested role was not found.")
		case errors.Is(err, repository.ErrSystemRoleImmutable):
			httpx.WriteProblem(w, http.StatusBadRequest, "Bad Request", "System roles cannot be modified or deleted.")
		case errors.Is(err, service.ErrPrivilegeEscalation):
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "Cannot grant platform permissions to tenant custom roles.")
		case errors.Is(err, service.ErrInvalidPermissionScope):
			httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "One or more permissions are invalid or unknown.")
		case errors.Is(err, repository.ErrDuplicateRoleName):
			httpx.WriteProblem(w, http.StatusConflict, "Role Already Exists", "A role with this name already exists in this tenant.")
		default:
			httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		}
		return
	}

	writeJSON(w, http.StatusOK, formatRole(role))
}

func (h *RoleHandler) DeleteCustomTenantRole(w http.ResponseWriter, r *http.Request) {
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok {
		httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
		return
	}

	tenantID, err := uuid.Parse(r.PathValue("tenantID"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant ID must be a valid UUID.")
		return
	}
	roleID, err := uuid.Parse(r.PathValue("roleID"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Role ID must be a valid UUID.")
		return
	}

	if err := h.authzService.AuthorizeTenant(r.Context(), principal, tenantID, "role.delete"); err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
			return
		}
		if errors.Is(err, service.ErrForbidden) {
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "You are not authorized to delete roles in this tenant.")
			return
		}
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	err = h.roleService.DeleteCustomTenantRole(r.Context(), tenantID, roleID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrRoleNotFound):
			httpx.WriteProblem(w, http.StatusNotFound, "Role Not Found", "The requested role was not found.")
		case errors.Is(err, repository.ErrSystemRoleImmutable):
			httpx.WriteProblem(w, http.StatusBadRequest, "Bad Request", "System roles cannot be modified or deleted.")
		case errors.Is(err, repository.ErrRoleHasAssignments):
			httpx.WriteProblem(w, http.StatusConflict, "Role In Use", "Cannot delete role that is currently assigned to users.")
		default:
			httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *RoleHandler) ListUsersByRole(w http.ResponseWriter, r *http.Request) {
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok {
		httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
		return
	}

	tenantID, err := uuid.Parse(r.PathValue("tenantID"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant ID must be a valid UUID.")
		return
	}
	roleID, err := uuid.Parse(r.PathValue("roleID"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Role ID must be a valid UUID.")
		return
	}

	if err := h.authzService.AuthorizeTenant(r.Context(), principal, tenantID, "role.read"); err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
			return
		}
		if errors.Is(err, service.ErrForbidden) {
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "You are not authorized to view roles in this tenant.")
			return
		}
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	members, err := h.roleAssignRepo.ListUsersByTenantRole(r.Context(), tenantID, roleID)
	if err != nil {
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	items := make([]tenantMemberResponse, len(members))
	for i, m := range members {
		items[i] = tenantMemberResponse{
			UserID:    m.UserID.String(),
			Email:     m.Email,
			Status:    m.Status,
			RoleID:    m.RoleID.String(),
			RoleName:  m.RoleName,
			RoleScope: m.RoleScope,
			JoinedAt:  m.JoinedAt.Format(time.RFC3339),
		}
	}

	writeJSON(w, http.StatusOK, struct {
		Users []tenantMemberResponse `json:"users"`
	}{Users: items})
}
