package session

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
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
		{name: "XChaCha20-Poly1305", aead: newTestXChaCha20Poly1305(t)},
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
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(opened, plaintext) {
				t.Fatalf("opened = %q, want %q", opened, plaintext)
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

func TestCookieManager_AESGCMKeyRotation(t *testing.T) {
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
	cookies := seedResponse.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %#v", cookies)
	}

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
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(cookies[0])
	load.ServeHTTP(httptest.NewRecorder(), request)
}

func TestCookieManager_RoundTrip(t *testing.T) {
	aead := newTestAEAD(t)

	tests := []struct {
		name                 string
		data                 []byte
		expiresAt            time.Time
		compressionDisabled  bool
		expectCompression    bool
		expectSaveError      bool
		expectRoundTripError bool
	}{
		{
			name:              "Small data, no compression",
			data:              []byte("small test data"),
			expiresAt:         time.Now().Add(1 * time.Hour),
			expectCompression: false,
		},
		{
			name:              "Large data, with compression",
			data:              randBytes(managerMaxCookieSize - 1500),
			expiresAt:         time.Now().Add(1 * time.Hour),
			expectCompression: true,
		},
		{
			name:                 "Expired data",
			data:                 []byte("test data"),
			expiresAt:            time.Now().Add(-1 * time.Hour),
			expectRoundTripError: true,
		},
		{
			name:                "Large data, compression disabled",
			data:                randBytes(managerMaxCookieSize - 1500),
			expiresAt:           time.Now().Add(1 * time.Hour),
			compressionDisabled: true,
			expectCompression:   false,
		},
		{
			name:              "Data just below compression threshold",
			data:              bytes.Repeat([]byte("a"), managerCompressThreshold-9),
			expiresAt:         time.Now().Add(1 * time.Hour),
			expectCompression: false,
		},
		{
			name:              "Empty data",
			data:              []byte{},
			expiresAt:         time.Now().Add(1 * time.Hour),
			expectCompression: false,
		},
		{
			name:              "Binary data with zero bytes",
			data:              []byte{0, 1, 2, 0, 3, 4},
			expiresAt:         time.Now().Add(1 * time.Hour),
			expectCompression: false,
		},
		{
			name:              "Almost expiring data",
			data:              []byte("test data"),
			expiresAt:         time.Now().Add(1 * time.Second),
			expectCompression: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, err := NewCookieManager[testSessionData](aead, &CookieManagerOpts[testSessionData]{
				DisableCompression: tt.compressionDisabled})

			if err != nil {
				t.Fatal(err)
			}
			cs := mgr.store.(*cookieStore[testSessionData])

			w := httptest.NewRecorder()

			err = cookieStoreRoundTripSave(cs, w, tt.expiresAt, tt.data)
			if tt.expectSaveError {
				if err == nil {
					t.Error("Expected save error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error saving cookie: %v", err)
			}

			// Get the cookie from the response
			cookies := w.Result().Cookies()
			if len(cookies) == 0 {
				t.Fatal("No cookies set in response")
			}

			// Verify the cookie value has the expected magic prefix
			cookieValue := cookies[0].Value
			parts := strings.SplitN(cookieValue, ".", 2)
			if len(parts) != 2 {
				t.Fatalf("Invalid cookie format: %s", cookieValue)
			}

			actualMagic := parts[0]
			expectedMagic := managerCookieMagic
			if tt.expectCompression {
				expectedMagic = managerCompressedCookieMagic
			}

			if actualMagic != expectedMagic {
				t.Errorf("Expected cookie magic %s, got %s", expectedMagic, actualMagic)
			}

			// Load the cookie back
			loadedData, err := cookieStoreRoundTripLoad(cs, cookieValue)

			if tt.expectRoundTripError {
				if err == nil {
					t.Error("Expected load error due to expiration, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error loading cookie: %v", err)
			}

			// Verify that the data matches what we saved
			if !bytes.Equal(loadedData, tt.data) {
				t.Errorf("Data mismatch after round trip:\nExpected: %v\nGot: %v", tt.data, loadedData)
			}
		})
	}
}

// TestCookieManager_ExtremelyLargeData tests that very large data causes an error
func TestCookieManager_ExtremelyLargeData(t *testing.T) {
	aead := newTestAEAD(t)

	// Create a manager
	mgr, err := NewCookieManager[testSessionData](aead, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs := mgr.store.(*cookieStore[testSessionData])

	largeData := randBytes(managerMaxCookieSize)
	expiresAt := time.Now().Add(1 * time.Hour)

	w := httptest.NewRecorder()

	err = cookieStoreRoundTripSave(cs, w, expiresAt, largeData)
	if err == nil {
		// If no error, verify that the cookie size is actually large
		cookies := w.Result().Cookies()
		if len(cookies) > 0 {
			if len(cookies[0].Value) <= managerMaxCookieSize {
				t.Logf("Cookie size: %d, max allowed: %d", len(cookies[0].Value), managerMaxCookieSize)
				t.Errorf("Generated cookie is smaller than the max size (%d <= %d), adjust test data size",
					len(cookies[0].Value), managerMaxCookieSize)
			} else {
				t.Errorf("Cookie size %d exceeds max %d but no error was returned",
					len(cookies[0].Value), managerMaxCookieSize)
			}
		}
	}
}

// TestCookieManager_MultipleRoundTrips tests that data can be saved and loaded multiple times
func TestCookieManager_MultipleRoundTrips(t *testing.T) {
	aead := newTestAEAD(t)

	// Create a manager
	mgr, err := NewCookieManager[testSessionData](aead, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs := mgr.store.(*cookieStore[testSessionData])

	originalData := []byte("test data for multiple round trips")
	expiresAt := time.Now().Add(1 * time.Hour)

	w1 := httptest.NewRecorder()

	err = cookieStoreRoundTripSave(cs, w1, expiresAt, originalData)
	if err != nil {
		t.Fatalf("Error in first save: %v", err)
	}

	cookies1 := w1.Result().Cookies()
	loadedData1, err := cookieStoreRoundTripLoad(cs, cookies1[0].Value)
	if err != nil {
		t.Fatalf("Error in first load: %v", err)
	}

	if !bytes.Equal(loadedData1, originalData) {
		t.Errorf("Data mismatch after first round trip")
	}

	// Round trip 2 - using the loaded data as input
	w2 := httptest.NewRecorder()

	err = cookieStoreRoundTripSave(cs, w2, expiresAt, loadedData1)
	if err != nil {
		t.Fatalf("Error in second save: %v", err)
	}

	cookies2 := w2.Result().Cookies()
	loadedData2, err := cookieStoreRoundTripLoad(cs, cookies2[0].Value)
	if err != nil {
		t.Fatalf("Error in second load: %v", err)
	}

	if !bytes.Equal(loadedData2, originalData) {
		t.Errorf("Data mismatch after second round trip")
	}
}

// TestCookieManager_CompressionLogic tests the compression logic specifically
func TestCookieManager_CompressionLogic(t *testing.T) {
	aead := newTestAEAD(t)

	// Create a manager
	mgr, err := NewCookieManager[testSessionData](aead, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs := mgr.store.(*cookieStore[testSessionData])

	largeData := bytes.Repeat([]byte("a"), managerCompressThreshold+1)
	expiresAt := time.Now().Add(1 * time.Hour)

	w := httptest.NewRecorder()

	err = cookieStoreRoundTripSave(cs, w, expiresAt, largeData)
	if err != nil {
		t.Fatalf("Error saving cookie: %v", err)
	}

	// Get cookie value and check the magic
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("No cookies set")
	}

	cookieValue := cookies[0].Value
	t.Logf("Cookie value: %s", cookieValue)

	parts := strings.SplitN(cookieValue, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("Invalid cookie format: %s", cookieValue)
	}

	magic := parts[0]
	t.Logf("Magic: %s, expected compressed cookie format", magic)

	if magic != managerCompressedCookieMagic {
		t.Errorf("Expected cookie magic %s for compression, got %s",
			managerCompressedCookieMagic, magic)
	}

	// Now try to load it back
	loadedData, err := cookieStoreRoundTripLoad(cs, cookieValue)
	if err != nil {
		t.Fatalf("Error loading cookie: %v", err)
	}

	// Verify data round-tripped correctly
	if !bytes.Equal(loadedData, largeData) {
		t.Error("Data mismatch after compression round-trip")
	}
}

// TestCookieManager_MaxSize tests the cookie max size limit
func TestCookieManager_MaxSize(t *testing.T) {
	aead := newTestAEAD(t)

	// Create a manager
	mgr, err := NewCookieManager[testSessionData](aead, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs := mgr.store.(*cookieStore[testSessionData])

	sizes := []int{1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000}
	expiresAt := time.Now().Add(1 * time.Hour)

	for _, size := range sizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			data := randBytes(size)

			w := httptest.NewRecorder()

			err = cookieStoreRoundTripSave(cs, w, expiresAt, data)

			if err != nil {
				if strings.Contains(err.Error(), "cookie size") {
					t.Logf("Size %d exceeded cookie size limit as expected", size)
				} else {
					t.Errorf("Unexpected error for size %d: %v", size, err)
				}
				return
			}

			// If no error, check cookie size
			cookies := w.Result().Cookies()
			if len(cookies) > 0 {
				cookieSize := len(cookies[0].Value)
				t.Logf("Cookie size for data size %d: %d bytes (max: %d)",
					size, cookieSize, managerMaxCookieSize)

				if cookieSize > managerMaxCookieSize {
					t.Errorf("Cookie size %d exceeds max %d but no error",
						cookieSize, managerMaxCookieSize)
				}
			}
		})
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

// cookieStoreRoundTripSave and cookieStoreRoundTripLoad exercise the low-level
// cookie encrypt/compress/format path without going through persistedSession.
// They live in the test file so production code stays on cookieStore methods.
func cookieStoreRoundTripSave(cs *cookieStore[testSessionData], w http.ResponseWriter, expiresAt time.Time, data []byte) error {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(expiresAt.Unix()))
	dataWithExpiry := append(b, data...)

	magic := managerCookieMagic
	if !cs.compressionDisabled && len(dataWithExpiry) > managerCompressThreshold {
		cw := getCompressor()
		defer putCompressor(cw)

		compressed, err := cw.Compress(dataWithExpiry)
		if err != nil {
			return fmt.Errorf("compressing cookie: %w", err)
		}
		dataWithExpiry = compressed
		magic = managerCompressedCookieMagic
	}

	encryptedData, err := sealAEAD(cs.aead, dataWithExpiry, []byte(cs.cookieSettings.Name))
	if err != nil {
		return fmt.Errorf("encrypting cookie failed: %w", err)
	}

	cookieValue := magic + ".." + managerCookieValueEncoding.EncodeToString(encryptedData)
	if len(cookieValue) > managerMaxCookieSize {
		return fmt.Errorf("cookie size %d is greater than max %d", len(cookieValue), managerMaxCookieSize)
	}

	cookie := cs.cookieSettings.newCookie(expiresAt)
	cookie.Value = cookieValue
	http.SetCookie(w, cookie)
	return nil
}

func cookieStoreRoundTripLoad(cs *cookieStore[testSessionData], cookieValue string) ([]byte, error) {
	sp := strings.SplitN(cookieValue, ".", 3)
	if len(sp) != 3 {
		if len(sp) == 2 {
			sp = []string{sp[0], "", sp[1]}
		} else {
			return nil, errors.New("cookie does not contain expected dot-separated parts")
		}
	}

	magic := sp[0]
	encodedData := sp[2]

	decodedData, err := managerCookieValueEncoding.DecodeString(encodedData)
	if err != nil {
		return nil, fmt.Errorf("decoding cookie string: %w", err)
	}

	decryptedData, err := openAEAD(cs.aead, decodedData, []byte(cs.cookieSettings.Name))
	if err != nil {
		return nil, fmt.Errorf("decrypting cookie: %w", err)
	}

	var rawData []byte
	if magic == managerCompressedCookieMagic {
		cr := getDecompressor()
		defer putDecompressor(cr)
		b, err := cr.Decompress(decryptedData)
		if err != nil {
			return nil, fmt.Errorf("decompressing cookie: %w", err)
		}
		rawData = b
	} else {
		rawData = decryptedData
	}

	if len(rawData) < 8 {
		return nil, errors.New("decrypted data too short")
	}
	expiresAt := time.Unix(int64(binary.LittleEndian.Uint64(rawData[:8])), 0)
	if expiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("cookie expired at %s", expiresAt)
	}

	return rawData[8:], nil
}
