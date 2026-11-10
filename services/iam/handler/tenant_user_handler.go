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

type TenantUserHandler struct {
	tenantUserService *service.TenantUserService
	roleAssignService *service.RoleAssignmentService
}

func NewTenantUserHandler(
	tenantUserService *service.TenantUserService,
	roleAssignService *service.RoleAssignmentService,
) *TenantUserHandler {
	return &TenantUserHandler{
		tenantUserService: tenantUserService,
		roleAssignService: roleAssignService,
	}
}

type tenantMemberResponse struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	Status    string `json:"status"`
	RoleID    string `json:"role_id"`
	RoleName  string `json:"role_name"`
	RoleScope string `json:"role_scope"`
	JoinedAt  string `json:"joined_at"`
}

type provisionTenantUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	RoleID   string `json:"role_id"`
}

type addMemberRequest struct {
	UserID string `json:"user_id"`
	RoleID string `json:"role_id"`
}

type changeRoleRequest struct {
	RoleID string `json:"role_id"`
}

func formatMember(m *model.TenantMemberRecord) tenantMemberResponse {
	return tenantMemberResponse{
		UserID:    m.UserID.String(),
		Email:     m.Email,
		Status:    m.Status,
		RoleID:    m.RoleID.String(),
		RoleName:  m.RoleName,
		RoleScope: m.RoleScope,
		JoinedAt:  m.JoinedAt.Format(time.RFC3339),
	}
}

func (h *TenantUserHandler) ProvisionUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok || principal == nil || !principal.IsValid() {
		httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
		return
	}

	tenantID, err := uuid.Parse(r.PathValue("tenantID"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant ID must be a valid UUID.")
		return
	}

	var req provisionTenantUserRequest
	if err := decodeJSON(w, r, &req); err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Request body must contain valid JSON.")
		return
	}

	email := strings.TrimSpace(req.Email)
	if !isValidEmail(email) {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "A valid email address is required.")
		return
	}

	if len(req.Password) < 8 || len(req.Password) > 128 {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Password must be between 8 and 128 characters.")
		return
	}

	roleID, err := uuid.Parse(strings.TrimSpace(req.RoleID))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "role_id must be a valid UUID.")
		return
	}

	member, err := h.tenantUserService.ProvisionTenantUser(r.Context(), principal, tenantID, email, req.Password, roleID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrTenantNotFound):
			httpx.WriteProblem(w, http.StatusNotFound, "Tenant Not Found", "The requested tenant was not found.")
		case errors.Is(err, service.ErrInactiveTenant):
			httpx.WriteProblem(w, http.StatusBadRequest, "Inactive Tenant", "The target tenant is deactivated or suspended.")
		case errors.Is(err, service.ErrRoleNotFound):
			httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Role", "The specified role does not exist.")
		case errors.Is(err, service.ErrPrivilegeEscalation):
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "Platform roles cannot be assigned to tenant users.")
		case errors.Is(err, service.ErrInvalidRoleForTenant):
			httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Role", "The specified custom role does not belong to this tenant.")
		case errors.Is(err, service.ErrCannotDelegateRole):
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "You do not have authority to delegate one or more permissions in this role.")
		case errors.Is(err, service.ErrUserAlreadyExists):
			httpx.WriteProblem(w, http.StatusConflict, "User Already Exists", "A user with this email already exists.")
		case errors.Is(err, service.ErrForbidden):
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "You do not have permission to provision users.")
		default:
			httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		}
		return
	}

	writeJSON(w, http.StatusCreated, formatMember(member))
}

func (h *TenantUserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	tenantID, err := uuid.Parse(r.PathValue("tenantID"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant ID must be a valid UUID.")
		return
	}

	offset, limit := parsePagination(r)
	page := (offset / limit) + 1

	members, total, err := h.tenantUserService.ListTenantMembers(r.Context(), tenantID, offset, limit)
	if err != nil {
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	items := make([]tenantMemberResponse, len(members))
	for i := range members {
		items[i] = formatMember(&members[i])
	}

	writeJSON(w, http.StatusOK, struct {
		Users []tenantMemberResponse `json:"users"`
		Total int                    `json:"total"`
		Page  int                    `json:"page"`
		Limit int                    `json:"limit"`
	}{
		Users: items,
		Total: total,
		Page:  page,
		Limit: limit,
	})
}

func (h *TenantUserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	tenantID, err := uuid.Parse(r.PathValue("tenantID"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant ID must be a valid UUID.")
		return
	}
	userID, err := uuid.Parse(r.PathValue("userID"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "User ID must be a valid UUID.")
		return
	}

	member, err := h.tenantUserService.GetTenantMember(r.Context(), tenantID, userID)
	if err != nil {
		if errors.Is(err, service.ErrMemberNotFound) {
			httpx.WriteProblem(w, http.StatusNotFound, "User Not Found", "The user is not a member of this tenant.")
			return
		}
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	writeJSON(w, http.StatusOK, formatMember(member))
}

// AddMember allows platform admins to assign an existing user to any tenant.
func (h *TenantUserHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok || principal == nil || !principal.IsValid() {
		httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
		return
	}

	tenantID, err := uuid.Parse(r.PathValue("tenantID"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant ID must be a valid UUID.")
		return
	}

	var req addMemberRequest
	if err := decodeJSON(w, r, &req); err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Request body must contain valid JSON.")
		return
	}

	userID, err := uuid.Parse(strings.TrimSpace(req.UserID))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "user_id must be a valid UUID.")
		return
	}
	roleID, err := uuid.Parse(strings.TrimSpace(req.RoleID))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "role_id must be a valid UUID.")
		return
	}

	member, err := h.tenantUserService.AddTenantMember(r.Context(), principal, tenantID, userID, roleID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrTenantNotFound):
			httpx.WriteProblem(w, http.StatusNotFound, "Tenant Not Found", "The requested tenant was not found.")
		case errors.Is(err, service.ErrInactiveTenant):
			httpx.WriteProblem(w, http.StatusBadRequest, "Inactive Tenant", "The target tenant is deactivated or suspended.")
		case errors.Is(err, repository.ErrNotFound):
			httpx.WriteProblem(w, http.StatusNotFound, "User Not Found", "The requested user was not found.")
		case errors.Is(err, service.ErrInactiveUser):
			httpx.WriteProblem(w, http.StatusBadRequest, "Inactive User", "The requested user is deactivated.")
		case errors.Is(err, service.ErrRoleNotFound):
			httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Role", "The specified role does not exist.")
		case errors.Is(err, service.ErrPrivilegeEscalation):
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "Platform roles cannot be assigned to tenant users.")
		case errors.Is(err, service.ErrInvalidRoleForTenant):
			httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Role", "The specified custom role does not belong to this tenant.")
		case errors.Is(err, service.ErrCannotDelegateRole):
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "You do not have authority to delegate this role.")
		case errors.Is(err, service.ErrForbidden):
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "Only platform admins can assign existing users to a tenant.")
		default:
			httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		}
		return
	}

	writeJSON(w, http.StatusOK, formatMember(member))
}

// ChangeRole updates a member's role within a tenant.
func (h *TenantUserHandler) ChangeRole(w http.ResponseWriter, r *http.Request) {
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok || principal == nil || !principal.IsValid() {
		httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
		return
	}

	tenantID, err := uuid.Parse(r.PathValue("tenantID"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant ID must be a valid UUID.")
		return
	}
	userID, err := uuid.Parse(r.PathValue("userID"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "User ID must be a valid UUID.")
		return
	}

	var req changeRoleRequest
	if err := decodeJSON(w, r, &req); err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Request body must contain valid JSON.")
		return
	}

	roleID, err := uuid.Parse(strings.TrimSpace(req.RoleID))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "role_id must be a valid UUID.")
		return
	}

	member, err := h.tenantUserService.ChangeTenantUserRole(r.Context(), principal, tenantID, userID, roleID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrTenantNotFound):
			httpx.WriteProblem(w, http.StatusNotFound, "Tenant Not Found", "The requested tenant was not found.")
		case errors.Is(err, service.ErrMemberNotFound):
			httpx.WriteProblem(w, http.StatusNotFound, "Member Not Found", "The user is not a member of this tenant.")
		case errors.Is(err, service.ErrRoleNotFound):
			httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Role", "The specified role does not exist.")
		case errors.Is(err, service.ErrPrivilegeEscalation):
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "Platform roles cannot be assigned to tenant users.")
		case errors.Is(err, service.ErrInvalidRoleForTenant):
			httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Role", "The specified custom role does not belong to this tenant.")
		case errors.Is(err, service.ErrCannotDelegateRole):
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "You do not have authority to delegate this role.")
		case errors.Is(err, service.ErrInactiveUser):
			httpx.WriteProblem(w, http.StatusBadRequest, "Inactive User", "The target user is inactive.")
		case errors.Is(err, service.ErrCannotRemoveLastAdmin):
			httpx.WriteProblem(w, http.StatusConflict, "Last Tenant Admin", "Cannot remove or demote the last active tenant administrator.")
		default:
			httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		}
		return
	}

	writeJSON(w, http.StatusOK, formatMember(member))
}

// RemoveMember removes a user from a tenant.
func (h *TenantUserHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok || principal == nil || !principal.IsValid() {
		httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
		return
	}

	tenantID, err := uuid.Parse(r.PathValue("tenantID"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant ID must be a valid UUID.")
		return
	}
	userID, err := uuid.Parse(r.PathValue("userID"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "User ID must be a valid UUID.")
		return
	}

	err = h.tenantUserService.RemoveTenantMember(r.Context(), principal, tenantID, userID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrMemberNotFound):
			httpx.WriteProblem(w, http.StatusNotFound, "Member Not Found", "The user is not a member of this tenant.")
		case errors.Is(err, service.ErrCannotRemoveLastAdmin):
			httpx.WriteProblem(w, http.StatusConflict, "Last Tenant Admin", "Cannot remove or demote the last active tenant administrator.")
		case errors.Is(err, service.ErrForbidden):
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "You do not have permission to remove members from this tenant.")
		default:
			httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
