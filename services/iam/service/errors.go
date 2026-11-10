package service

import "errors"

var (
	// ErrUnauthorized indicates missing or invalid principal credentials.
	ErrUnauthorized = errors.New("unauthorized: missing or invalid principal")

	// ErrForbidden indicates the principal lacks required authorization or delegation authority.
	ErrForbidden = errors.New("forbidden: insufficient permissions")
)
