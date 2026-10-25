package httpx_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nooman57554/The_Orb/orb_libs/httpx"
)

func TestWriteProblem_BasicResponse(t *testing.T) {
	rec := httptest.NewRecorder()
	httpx.WriteProblem(rec, http.StatusBadRequest, "Invalid Request", "User ID is required.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/problem+json" {
		t.Errorf("expected Content-Type application/problem+json, got %s", contentType)
	}

	var prob httpx.ProblemDetails
	if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
		t.Fatalf("failed to decode problem JSON: %v", err)
	}

	if prob.Type != "https://orb.example.com/problems/invalid-request" {
		t.Errorf("expected type https://orb.example.com/problems/invalid-request, got %s", prob.Type)
	}
	if prob.Title != "Invalid Request" {
		t.Errorf("expected title 'Invalid Request', got %s", prob.Title)
	}
	if prob.Status != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, prob.Status)
	}
	if prob.Detail != "User ID is required." {
		t.Errorf("expected detail 'User ID is required.', got %s", prob.Detail)
	}
}

func TestWriteProblem_EmptyDetail_Omitted(t *testing.T) {
	rec := httptest.NewRecorder()
	httpx.WriteProblem(rec, http.StatusUnauthorized, "Unauthorized", "")

	raw := rec.Body.String()
	var rawMap map[string]any
	if err := json.Unmarshal([]byte(raw), &rawMap); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if _, exists := rawMap["detail"]; exists {
		t.Errorf("expected 'detail' field to be omitted when empty, got %v", rawMap["detail"])
	}
}

func TestWriteProblem_StableSlugs(t *testing.T) {
	cases := []struct {
		title        string
		status       int
		expectedType string
	}{
		{
			title:        "Invalid Request",
			status:       http.StatusBadRequest,
			expectedType: "https://orb.example.com/problems/invalid-request",
		},
		{
			title:        "User Already Exists",
			status:       http.StatusConflict,
			expectedType: "https://orb.example.com/problems/user-already-exists",
		},
		{
			title:        "User Not Found",
			status:       http.StatusNotFound,
			expectedType: "https://orb.example.com/problems/user-not-found",
		},
		{
			title:        "Unauthorized",
			status:       http.StatusUnauthorized,
			expectedType: "https://orb.example.com/problems/unauthorized",
		},
		{
			title:        "Forbidden",
			status:       http.StatusForbidden,
			expectedType: "https://orb.example.com/problems/forbidden",
		},
		{
			title:        "Service Unavailable",
			status:       http.StatusServiceUnavailable,
			expectedType: "https://orb.example.com/problems/service-unavailable",
		},
		{
			title:        "Internal Server Error",
			status:       http.StatusInternalServerError,
			expectedType: "https://orb.example.com/problems/internal-server-error",
		},
		{
			title:        "Invalid Credentials",
			status:       http.StatusUnauthorized,
			expectedType: "https://orb.example.com/problems/invalid-credentials",
		},
		{
			title:        "Invalid Refresh Token",
			status:       http.StatusUnauthorized,
			expectedType: "https://orb.example.com/problems/invalid-refresh-token",
		},
	}

	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			rec := httptest.NewRecorder()
			httpx.WriteProblem(rec, tc.status, tc.title, "test detail")

			var prob httpx.ProblemDetails
			if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
				t.Fatalf("failed to decode JSON: %v", err)
			}

			if prob.Type != tc.expectedType {
				t.Errorf("expected type %s, got %s", tc.expectedType, prob.Type)
			}
			if prob.Status != tc.status {
				t.Errorf("expected status %d, got %d", tc.status, prob.Status)
			}
		})
	}
}

func TestWriteProblem_DeterministicFallbackForUnknownTitles(t *testing.T) {
	unknownTitles := []string{
		"Payment Required",
		"Gateway Timeout",
		"Something Arbitrary",
		"",
	}

	expectedFallback := "https://orb.example.com/problems/internal-error"

	for _, title := range unknownTitles {
		t.Run("unknown_"+title, func(t *testing.T) {
			rec := httptest.NewRecorder()
			httpx.WriteProblem(rec, http.StatusInternalServerError, title, "unexpected failure")

			var prob httpx.ProblemDetails
			if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
				t.Fatalf("failed to decode JSON: %v", err)
			}

			if prob.Type != expectedFallback {
				t.Errorf("expected fallback type %s, got %s", expectedFallback, prob.Type)
			}
		})
	}
}
