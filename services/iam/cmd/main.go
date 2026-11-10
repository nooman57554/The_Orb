package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/nooman57554/The_Orb/orb_libs/authorization"
	"github.com/nooman57554/The_Orb/orb_libs/dbconnector"
	"github.com/nooman57554/The_Orb/orb_libs/identity/httpauth"
	"github.com/nooman57554/The_Orb/orb_libs/identity/jwtverify"
	"github.com/nooman57554/The_Orb/services/iam/auth"
	"github.com/nooman57554/The_Orb/services/iam/config"
	"github.com/nooman57554/The_Orb/services/iam/handler"
	"github.com/nooman57554/The_Orb/services/iam/keyloader"
	"github.com/nooman57554/The_Orb/services/iam/middleware"
	"github.com/nooman57554/The_Orb/services/iam/repository"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

func main() {
	ctx := context.Background()

	// load config
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load IAM configuration: %v", err)
	}

	// create DB connection pool
	db, err := dbconnector.New(ctx, cfg.DatabaseConfig())
	if err != nil {
		log.Fatalf("create database connector: %v", err)
	}
	defer db.Close()

	// initialize JWT manager and verifier
	jwtManager, tokenVerifier, err := initAuth(cfg)
	if err != nil {
		log.Fatalf("initialize JWT auth: %v", err)
	}

	// create repositories
	outboxRepo := repository.NewPostgresOutboxRepository(db)
	userRepo := repository.NewPostgresUserRepository(db, outboxRepo)
	sessionRepo := repository.NewPostgresSessionRepository(db)
	authzRepo := repository.NewPostgresAuthorizationRepository(db)
	tenantRepo := repository.NewPostgresTenantRepository(db, outboxRepo)
	roleRepo := repository.NewPostgresRoleRepository(db, outboxRepo)
	permRepo := repository.NewPostgresPermissionRepository(db)
	roleAssignRepo := repository.NewPostgresRoleAssignmentRepository(db, outboxRepo)
	snapshotLoader := repository.NewPostgresSnapshotLoader(db)

	// initialize policy distribution service and bootstrap initial snapshot
	policyDistService, err := service.NewPolicyDistributionService(snapshotLoader)
	if err != nil {
		log.Fatalf("initialize policy distribution service: %v", err)
	}
	if err := policyDistService.Bootstrap(ctx); err != nil {
		log.Printf("warning: policy snapshot bootstrap failed (fail-closed until snapshot loaded): %v", err)
	}

	// create core domain services
	authzService, err := service.NewAuthorizationService(policyDistService.Engine())
	if err != nil {
		log.Fatalf("initialize authorization service: %v", err)
	}

	roleAssignService, err := service.NewRoleAssignmentService(
		roleAssignRepo,
		roleRepo,
		userRepo,
		tenantRepo,
		authzRepo,
	)
	if err != nil {
		log.Fatalf("initialize role assignment service: %v", err)
	}

	roleService, err := service.NewRoleService(
		roleRepo,
		permRepo,
		roleAssignService,
	)
	if err != nil {
		log.Fatalf("initialize role service: %v", err)
	}

	tenantService, err := service.NewTenantService(tenantRepo)
	if err != nil {
		log.Fatalf("initialize tenant service: %v", err)
	}

	tenantUserService, err := service.NewTenantUserService(
		userRepo,
		tenantRepo,
		roleRepo,
		roleAssignService,
		authzRepo,
	)
	if err != nil {
		log.Fatalf("initialize tenant user service: %v", err)
	}

	userService := service.NewUserService(userRepo)
	authService, err := service.NewAuthService(
		userRepo,
		sessionRepo,
		jwtManager,
		cfg.JWTTTL,
		cfg.RefreshTokenTTL,
		cfg.RefreshReuseGracePeriod,
	)
	if err != nil {
		log.Fatalf("initialize auth service: %v", err)
	}

	// initialize unified route authorizer middleware
	authorizer, err := middleware.NewAuthorizer(policyDistService.Engine())
	if err != nil {
		log.Fatalf("initialize authorizer middleware: %v", err)
	}

	// create handlers
	authHandler := handler.NewAuthHandler(authService)
	authzHandler := handler.NewAuthorizationHandler(authzService)
	permHandler := handler.NewPermissionHandler(roleService, authzService)
	roleHandler := handler.NewRoleHandler(roleService, roleAssignService)
	tenantHandler := handler.NewTenantHandler(tenantService)
	tenantUserHandler := handler.NewTenantUserHandler(tenantUserService, roleAssignService)
	userHandler := handler.NewUserHandler(userService, authzService)

	// create bearer middleware with default-protected routing and explicit public exemptions
	bearerMiddleware, err := httpauth.NewBearerMiddleware(
		tokenVerifier,
		sessionRepo,
		"POST /v1/auth/login",
		"POST /v1/auth/refresh",
		"POST /v1/auth/logout",
		"POST /v1/users",
	)
	if err != nil {
		log.Fatalf("initialize bearer middleware: %v", err)
	}

	// Create router
	mux := http.NewServeMux()

	// Auth routes (public)
	mux.HandleFunc("POST /v1/auth/login", authHandler.Login)
	mux.HandleFunc("POST /v1/auth/refresh", authHandler.Refresh)
	mux.HandleFunc("POST /v1/auth/logout", authHandler.Logout)

	// Authorization Check route
	mux.HandleFunc("POST /v1/authorization/check", authzHandler.Check)

	// Permission Catalog routes
	mux.HandleFunc("GET /v1/permissions", permHandler.ListPermissions)

	// Platform Role routes
	mux.HandleFunc("GET /v1/platform-roles", authorizer.Require(authorization.PermPlatformRoleRead)(roleHandler.ListPlatformRoles))
	mux.HandleFunc("PUT /v1/users/{id}/platform-role", authorizer.Require(authorization.PermPlatformRoleAssign)(roleHandler.AssignPlatformRole))
	mux.HandleFunc("DELETE /v1/users/{id}/platform-role", authorizer.Require(authorization.PermPlatformRoleAssign)(roleHandler.RemovePlatformRole))
	mux.HandleFunc("GET /v1/users/{id}/platform-role", authorizer.Require(authorization.PermPlatformRoleRead)(roleHandler.GetPlatformRole))

	// Tenant Role routes
	mux.HandleFunc("GET /v1/tenants/{tenantID}/roles", authorizer.Require(authorization.PermTenantRoleRead, authorization.RouteParam("tenantID"))(roleHandler.ListTenantRoles))
	mux.HandleFunc("POST /v1/tenants/{tenantID}/roles", authorizer.Require(authorization.PermTenantRoleCreate, authorization.RouteParam("tenantID"))(roleHandler.CreateCustomTenantRole))
	mux.HandleFunc("GET /v1/tenants/{tenantID}/roles/{roleID}", authorizer.Require(authorization.PermTenantRoleRead, authorization.RouteParam("tenantID"))(roleHandler.GetTenantRole))
	mux.HandleFunc("PATCH /v1/tenants/{tenantID}/roles/{roleID}", authorizer.Require(authorization.PermTenantRoleUpdate, authorization.RouteParam("tenantID"))(roleHandler.UpdateCustomTenantRole))
	mux.HandleFunc("DELETE /v1/tenants/{tenantID}/roles/{roleID}", authorizer.Require(authorization.PermTenantRoleDelete, authorization.RouteParam("tenantID"))(roleHandler.DeleteCustomTenantRole))
	mux.HandleFunc("GET /v1/tenants/{tenantID}/roles/{roleID}/users", authorizer.Require(authorization.PermTenantRoleRead, authorization.RouteParam("tenantID"))(roleHandler.ListUsersByRole))

	// Tenant Lifecycle routes
	mux.HandleFunc("POST /v1/tenants", authorizer.Require(authorization.PermPlatformTenantCreate)(tenantHandler.CreateTenant))
	mux.HandleFunc("GET /v1/tenants", authorizer.Require(authorization.PermPlatformTenantList)(tenantHandler.ListTenants))
	mux.HandleFunc("GET /v1/tenants/{id}", authorizer.Require(authorization.PermTenantRead, authorization.RouteParam("id"))(tenantHandler.GetTenant))
	mux.HandleFunc("PATCH /v1/tenants/{id}", authorizer.Require(authorization.PermTenantUpdate, authorization.RouteParam("id"))(tenantHandler.UpdateTenant))
	mux.HandleFunc("POST /v1/tenants/{id}/deactivate", authorizer.Require(authorization.PermPlatformTenantDeactivate)(tenantHandler.DeactivateTenant))
	mux.HandleFunc("POST /v1/tenants/{id}/reactivate", authorizer.Require(authorization.PermPlatformTenantReactivate)(tenantHandler.ReactivateTenant))

	// Tenant User / Membership routes
	mux.HandleFunc("POST /v1/tenants/{tenantID}/users", authorizer.Require(authorization.PermTenantUserCreate, authorization.RouteParam("tenantID"))(tenantUserHandler.ProvisionUser))
	mux.HandleFunc("GET /v1/tenants/{tenantID}/users", authorizer.Require(authorization.PermTenantUserRead, authorization.RouteParam("tenantID"))(tenantUserHandler.ListUsers))
	mux.HandleFunc("GET /v1/tenants/{tenantID}/users/{userID}", authorizer.Require(authorization.PermTenantUserRead, authorization.RouteParam("tenantID"))(tenantUserHandler.GetUser))
	mux.HandleFunc("POST /v1/tenants/{tenantID}/members", authorizer.Require(authorization.PermPlatformRoleAssign)(tenantUserHandler.AddMember))
	mux.HandleFunc("PATCH /v1/tenants/{tenantID}/users/{userID}/role", authorizer.Require(authorization.PermTenantUserAssignRole, authorization.RouteParam("tenantID"))(tenantUserHandler.ChangeRole))
	mux.HandleFunc("DELETE /v1/tenants/{tenantID}/users/{userID}", authorizer.Require(authorization.PermTenantUserRemove, authorization.RouteParam("tenantID"))(tenantUserHandler.RemoveMember))

	// User routes
	mux.HandleFunc("POST /v1/users", userHandler.CreateUser)
	mux.HandleFunc("GET /v1/users/{id}", userHandler.GetUser)
	mux.HandleFunc("POST /v1/users/{id}/deactivate", authorizer.Require(authorization.PermPlatformUserDeactivate)(userHandler.DeactivateUser))
	mux.HandleFunc("POST /v1/users/{id}/reactivate", authorizer.Require(authorization.PermPlatformUserReactivate)(userHandler.ReactivateUser))

	server := &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      bearerMiddleware.Require(mux),
		ReadTimeout:  cfg.HTTPReadTimeout,
		WriteTimeout: cfg.HTTPWriteTimeout,
		IdleTimeout:  cfg.HTTPIdleTimeout,
	}

	log.Printf("IAM server starting on %s", cfg.HTTPAddr)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("IAM server failed: %v", err)
	}
}

func initAuth(cfg config.Config) (*auth.JWTManager, *jwtverify.Verifier, error) {
	keyLoader, err := keyloader.NewFileLoader(
		cfg.JWTPrivateKeyPath,
		cfg.JWTPublicKeysDir,
		cfg.JWTKeyID,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("configure JWT key loader: %w", err)
	}

	keySet, err := keyLoader.Load(context.Background())
	if err != nil {
		return nil, nil, fmt.Errorf("load JWT keys: %w", err)
	}

	jwtManager, err := auth.NewJWTManager(
		keySet.PrivateKey,
		keySet.ActiveKeyID,
		cfg.JWTIssuer,
		cfg.JWTAudience,
		cfg.JWTTTL,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize JWT manager: %w", err)
	}

	tokenVerifier, err := jwtverify.NewVerifier(
		keySet.PublicKeys,
		cfg.JWTIssuer,
		cfg.JWTAudience,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize token verifier: %w", err)
	}

	return jwtManager, tokenVerifier, nil
}
