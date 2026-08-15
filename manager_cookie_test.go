package session

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCookieManagerRequiresAEAD(t *testing.T) {
	if _, err := NewCookieManager[testSessionData](nil, nil); err == nil {
		t.Fatal("NewCookieManager accepted a nil AEAD")
	}
}

func TestAEADFraming(t *testing.T) {
	for _, tt := range []struct {
		name string
		aead cipher.AEAD
	}{
		{name: "AES-GCM", aead: newTestAESGCM(t, false)},
		{name: "AES-GCM random nonce", aead: newTestAESGCM(t, true)},
		{name: "AES-GCM 24-byte nonce", aead: newTestAESGCMWithNonceSize(t, 24)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			plaintext := []byte("session data")
			additionalData := []byte("cookie name")
			sealed, err := sealAEAD(tt.aead, plaintext, additionalData)
			if err != nil {
				t.Fatal(err)
			}
			wantLen := tt.aead.NonceSize() + len(plaintext) + tt.aead.Overhead()
			if len(sealed) != wantLen {
				t.Fatalf("sealed length = %d, want %d", len(sealed), wantLen)
			}
			opened, err := openAEAD(tt.aead, sealed, additionalData)
			if err != nil || !bytes.Equal(opened, plaintext) {
				t.Fatalf("opened = %q, %v", opened, err)
			}
			if _, err := openAEAD(tt.aead, sealed, []byte("another cookie")); err == nil {
				t.Fatal("ciphertext accepted with different additional data")
			}
			if _, err := openAEAD(tt.aead, sealed[:len(sealed)-1], additionalData); err == nil {
				t.Fatal("truncated ciphertext accepted")
			}
		})
	}
}

func TestCookieStoreRoundTrip(t *testing.T) {
	mgr, err := NewCookieManager[testSessionData](newTestAEAD(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	store := mgr.store.(*cookieStore[testSessionData])
	expiresAt := time.Now().Add(time.Hour)
	w := httptest.NewRecorder()
	want := persistedSession[testSessionData]{
		Data:      testSessionData{User: "alice", Number: 42},
		CreatedAt: time.Now(),
	}
	if err := store.save(w, httptest.NewRequest(http.MethodGet, "/", nil), expiresAt, want); err != nil {
		t.Fatal(err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !strings.HasPrefix(cookies[0].Value, managerCookieMagic+".") {
		t.Fatalf("saved cookies = %#v", cookies)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookies[0])
	got, encoded, err := store.load(r)
	if err != nil {
		t.Fatal(err)
	}
	if encoded == nil || got.Data != want.Data || !got.CreatedAt.Equal(want.CreatedAt) {
		t.Fatalf("loaded session = %#v, encoded %d bytes", got, len(encoded))
	}
}

func TestCookieStoreRejectsExpiredTamperedAndWrongContext(t *testing.T) {
	mgr, err := NewCookieManager[testSessionData](newTestAEAD(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	store := mgr.store.(*cookieStore[testSessionData])
	sess := persistedSession[testSessionData]{CreatedAt: time.Now()}

	t.Run("expired", func(t *testing.T) {
		w := httptest.NewRecorder()
		if err := store.save(w, httptest.NewRequest(http.MethodGet, "/", nil), time.Now().Add(-time.Second), sess); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(w.Result().Cookies()[0])
		_, encoded, err := store.load(r)
		if err != nil || encoded != nil {
			t.Fatalf("expired load = %d bytes, %v", len(encoded), err)
		}
	})

	t.Run("tampered", func(t *testing.T) {
		w := httptest.NewRecorder()
		if err := store.save(w, httptest.NewRequest(http.MethodGet, "/", nil), time.Now().Add(time.Hour), sess); err != nil {
			t.Fatal(err)
		}
		cookie := w.Result().Cookies()[0]
		parts := strings.SplitN(cookie.Value, ".", 2)
		sealed, err := managerCookieValueEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		sealed[len(sealed)/2] ^= 1
		cookie.Value = parts[0] + "." + managerCookieValueEncoding.EncodeToString(sealed)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(cookie)
		_, encoded, err := store.load(r)
		if err != nil || encoded != nil {
			t.Fatalf("tampered load = %d bytes, %v", len(encoded), err)
		}
	})

	t.Run("cookie name additional data", func(t *testing.T) {
		w := httptest.NewRecorder()
		if err := store.save(w, httptest.NewRequest(http.MethodGet, "/", nil), time.Now().Add(time.Hour), sess); err != nil {
			t.Fatal(err)
		}
		cookie := w.Result().Cookies()[0]
		cookie.Name = "other-session"
		other := *store
		other.cookieSettings.Name = cookie.Name
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(cookie)
		_, encoded, err := other.load(r)
		if err != nil || encoded != nil {
			t.Fatalf("cross-context load = %d bytes, %v", len(encoded), err)
		}
	})

	t.Run("short authenticated payload", func(t *testing.T) {
		sealed, err := sealAEAD(store.aead, []byte("short"), []byte(store.cookieSettings.Name))
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{
			Name:  store.cookieSettings.Name,
			Value: managerCookieMagic + "." + managerCookieValueEncoding.EncodeToString(sealed),
		})
		_, encoded, err := store.load(r)
		if err != nil || encoded != nil {
			t.Fatalf("short payload load = %d bytes, %v", len(encoded), err)
		}
	})
}

func TestCookieStoreRejectsOversizedValue(t *testing.T) {
	mgr, err := NewCookieManager[testSessionData](newTestAEAD(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	store := mgr.store.(*cookieStore[testSessionData])
	data := make([]byte, managerMaxSetCookieSize)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if err := store.writeCookie(httptest.NewRecorder(), time.Now().Add(time.Hour), data); err == nil {
		t.Fatal("oversized cookie accepted")
	}
}

func TestCookieManagerAESGCMKeyRotation(t *testing.T) {
	oldKey := bytes.Repeat([]byte{1}, 32)
	newKey := bytes.Repeat([]byte{2}, 32)
	oldAEAD, err := NewRotatingAESGCM(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	oldManager, err := NewCookieManager[testSessionData](oldAEAD, nil)
	if err != nil {
		t.Fatal(err)
	}
	seed := oldManager.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setTestUser(oldManager.FromContext(r.Context()), "alice")
	}))
	seedResponse := httptest.NewRecorder()
	seed.ServeHTTP(seedResponse, httptest.NewRequest(http.MethodGet, "/", nil))
	cookie := seedResponse.Result().Cookies()[0]

	rotatedAEAD, err := NewRotatingAESGCM(newKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	rotatedManager, err := NewCookieManager[testSessionData](rotatedAEAD, nil)
	if err != nil {
		t.Fatal(err)
	}
	load := rotatedManager.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := rotatedManager.FromContext(r.Context()).Get().User; got != "alice" {
			t.Fatalf("loaded user = %q, want alice", got)
		}
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookie)
	load.ServeHTTP(httptest.NewRecorder(), r)
}
