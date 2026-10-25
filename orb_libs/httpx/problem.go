package httpx

import (
	"encoding/json"
	"net/http"
)

const (
	ProblemContentType = "application/problem+json"
	ProblemTypePrefix  = "https://orb.example.com/problems/"
)

// ProblemDetails represents an RFC 7807 problem details response object.
type ProblemDetails struct {
	Type   string `json:"type,omitempty"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// WriteProblem writes an RFC 7807 problem response to the ResponseWriter with Content-Type application/problem+json.
// It maps known titles to stable problem-type URLs and uses a deterministic fallback for unknown titles.
func WriteProblem(
	w http.ResponseWriter,
	status int,
	title string,
	detail string,
) {
	w.Header().Set("Content-Type", ProblemContentType)
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(ProblemDetails{
		Type:   ProblemTypePrefix + titleToSlug(title),
		Title:  title,
		Status: status,
		Detail: detail,
	})
}

func titleToSlug(title string) string {
	switch title {
	case "Invalid Request":
		return "invalid-request"
	case "User Already Exists":
		return "user-already-exists"
	case "User Not Found":
		return "user-not-found"
	case "Unauthorized":
		return "unauthorized"
	case "Forbidden":
		return "forbidden"
	case "Service Unavailable":
		return "service-unavailable"
	case "Internal Server Error":
		return "internal-server-error"
	case "Invalid Credentials":
		return "invalid-credentials"
	case "Invalid Refresh Token":
		return "invalid-refresh-token"
	default:
		return "internal-error"
	}
}
