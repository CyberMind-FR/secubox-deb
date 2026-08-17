package main

import (
	"bytes"
	"io"
	"net/http"
	"strings"
)

func reponseHTML(corps string) *http.Response {
	h := http.Header{}
	h.Set("Content-Type", "text/html; charset=utf-8")
	return &http.Response{
		StatusCode:    200,
		Header:        h,
		Body:          io.NopCloser(strings.NewReader(corps)),
		ContentLength: int64(len(corps)),
	}
}

func lireCorps(r *http.Response) string {
	var b bytes.Buffer
	_, _ = io.Copy(&b, r.Body)
	return b.String()
}
