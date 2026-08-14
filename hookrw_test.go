package session

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHookRWForwardsOptionalInterfaces(t *testing.T) {
	recorder := httptest.NewRecorder()
	hookCalls := 0
	h := &hookRW{
		ResponseWriter: recorder,
		hook: func(http.ResponseWriter) bool {
			hookCalls++
			return true
		},
	}

	if _, err := h.ReadFrom(strings.NewReader("body")); err != nil {
		t.Fatal(err)
	}
	h.Flush()
	if hookCalls != 1 {
		t.Fatalf("hook called %d times, want 1", hookCalls)
	}
	if recorder.Body.String() != "body" || !recorder.Flushed {
		t.Fatalf("forwarded response = %q, flushed = %v", recorder.Body.String(), recorder.Flushed)
	}
	if _, _, err := h.Hijack(); !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("Hijack error = %v, want ErrNotSupported", err)
	}
	if err := h.Push("/asset", nil); !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("Push error = %v, want ErrNotSupported", err)
	}
}

func TestHookRWRemembersRejectedCommit(t *testing.T) {
	recorder := httptest.NewRecorder()
	hookCalls := 0
	h := &hookRW{
		ResponseWriter: recorder,
		hook: func(http.ResponseWriter) bool {
			hookCalls++
			return false
		},
	}

	if _, err := h.Write([]byte("first")); err == nil {
		t.Fatal("first write succeeded after rejected commit")
	}
	if _, err := h.Write([]byte("second")); err == nil {
		t.Fatal("second write succeeded after rejected commit")
	}
	if hookCalls != 1 {
		t.Fatalf("hook called %d times, want 1", hookCalls)
	}
	if recorder.Body.Len() != 0 {
		t.Fatalf("response body = %q, want empty", recorder.Body.String())
	}
}

func TestHookRWInformationalResponseDoesNotCommit(t *testing.T) {
	recorder := httptest.NewRecorder()
	hookCalls := 0
	h := &hookRW{
		ResponseWriter: recorder,
		hook: func(http.ResponseWriter) bool {
			hookCalls++
			return true
		},
	}

	h.WriteHeader(http.StatusEarlyHints)
	if h.responseCommitted() || hookCalls != 0 {
		t.Fatalf("103 response committed session: committed=%v, hook calls=%d", h.responseCommitted(), hookCalls)
	}
	h.WriteHeader(http.StatusOK)
	if !h.responseCommitted() || hookCalls != 1 {
		t.Fatalf("final response did not commit session: committed=%v, hook calls=%d", h.responseCommitted(), hookCalls)
	}
}
