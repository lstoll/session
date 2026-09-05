package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func saveTestUser(s *Session[testSessionData], value string) {
	s.Get().User = value
	s.Save()
}

func contractRequest(t *testing.T, handler http.Handler, cookies []*http.Cookie) (*httptest.ResponseRecorder, []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if got := recorder.Result().Cookies(); len(got) != 0 {
		cookies = got
	}
	return recorder, cookies
}
