package handler

import (
	"encoding/json"
	"net/http"
)

type problemDetails struct {
	Type   string `json:"type,omitempty"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func writeProblem(
	w http.ResponseWriter,
	status int,
	title string,
	detail string,
) {
	WriteProblem(w, status, title, detail)
}

func WriteProblem(
	w http.ResponseWriter,
	status int,
	title string,
	detail string,
) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(problemDetails{
		Type:   "https://orb.example.com/problems/" + titleToSlug(title),
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
