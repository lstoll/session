package session_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"lds.li/session"
)

type exampleSessionData struct {
	UserID string `json:"user_id"`
}

func ExampleManager() {
	sessions, err := session.NewKVManager[exampleSessionData](session.NewMemoryKV(), nil)
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		sess := sessions.FromContext(r.Context())
		sess.Reset()
		sess.Set(exampleSessionData{UserID: "alice"})
	})
	mux.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, sessions.FromContext(r.Context()).Get().UserID)
	})
	handler := sessions.Wrap(mux)

	loginResponse := httptest.NewRecorder()
	handler.ServeHTTP(loginResponse, httptest.NewRequest(http.MethodPost, "/login", nil))

	profileRequest := httptest.NewRequest(http.MethodGet, "/me", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		profileRequest.AddCookie(cookie)
	}
	profileResponse := httptest.NewRecorder()
	handler.ServeHTTP(profileResponse, profileRequest)

	fmt.Println(profileResponse.Body.String())
	// Output: alice
}
