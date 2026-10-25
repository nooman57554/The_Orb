package handler

import (
	"net/http"

	"github.com/nooman57554/The_Orb/orb_libs/httpx"
)

func writeProblem(
	w http.ResponseWriter,
	status int,
	title string,
	detail string,
) {
	httpx.WriteProblem(w, status, title, detail)
}

func WriteProblem(
	w http.ResponseWriter,
	status int,
	title string,
	detail string,
) {
	httpx.WriteProblem(w, status, title, detail)
}
