package session

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tink-crypto/tink-go/v2/tink"
)

type cookieStore struct {
	aead                tink.AEAD
	codec               codec
	compressionDisabled bool
	cookieSettings      SessionCookieOpts
}

func (s *cookieStore) load(r *http.Request) (persistedSession, []byte, error) {
	cookie, err := r.Cookie(s.cookieSettings.Name)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return persistedSession{}, nil, nil
		}
		return persistedSession{}, nil, fmt.Errorf("getting cookie %s: %w", s.cookieSettings.Name, err)
	}

	cookieValue := cookie.Value

	// Split and validate format: magic.boundCookieID.encodedData
	sp := strings.SplitN(cookieValue, ".", 3)
	if len(sp) != 3 {
		// Fallback for unbound cookies created with old 2-part format
		if len(sp) == 2 {
			sp = []string{sp[0], "", sp[1]}
		} else {
			return persistedSession{}, nil, errors.New("cookie does not contain expected dot-separated parts")
		}
	}

	magic := sp[0]
	boundCookieID := sp[1]
	encodedData := sp[2]

	// Decode
	decodedData, err := managerCookieValueEncoding.DecodeString(encodedData)
	if err != nil {
		return persistedSession{}, nil, fmt.Errorf("decoding cookie string: %w", err)
	}

	// Validate magic
	if magic != managerCompressedCookieMagic && magic != managerCookieMagic {
		return persistedSession{}, nil, fmt.Errorf("cookie has bad magic prefix: %s", magic)
	}

	// Determine Associated Data based on DBSC binding
	var ad []byte
	if boundCookieID != "" {
		ad = []byte(s.cookieSettings.Name + ":" + boundCookieID)
	} else {
		ad = []byte(s.cookieSettings.Name)
	}

	// Decrypt using AEAD with domain separated AD
	decryptedData, err := s.aead.Decrypt(decodedData, ad)
	if err != nil {
		return persistedSession{}, nil, fmt.Errorf("decrypting cookie: %w", err)
	}

	// Decompress if needed
	var rawData []byte
	if magic == managerCompressedCookieMagic {
		cr := getDecompressor()
		defer putDecompressor(cr)
		b, err := cr.Decompress(decryptedData)
		if err != nil {
			return persistedSession{}, nil, fmt.Errorf("decompressing cookie: %w", err)
		}
		rawData = b
	} else {
		rawData = decryptedData
	}

	// Check expiry
	if len(rawData) < 8 {
		return persistedSession{}, nil, errors.New("decrypted data too short")
	}
	expiresAt := time.Unix(int64(binary.LittleEndian.Uint64(rawData[:8])), 0)
	if expiresAt.Before(time.Now()) {
		return persistedSession{}, nil, fmt.Errorf("cookie expired at %s", expiresAt)
	}

	// Decode using the codec
	sess, err := s.codec.Decode(rawData[8:])
	if err != nil {
		return persistedSession{}, nil, fmt.Errorf("decoding session: %w", err)
	}

	// Populate derived/transient fields for the manager to use
	if len(sess.DBSCPublicJWKS) > 0 {
		sess.DBSCCurrentCookieID = boundCookieID
		sess.DBSCSessionID = deriveDBSCSessionID(sess.DBSCPublicJWKS)
	}

	return sess, rawData[8:], nil
}

func stripTransientDBSCFields(sess *persistedSession) string {
	boundCookieValue := sess.DBSCCurrentCookieID
	sess.DBSCRegistrationChallenge = ""
	sess.DBSCChallenge = ""
	sess.DBSCChallengeIssuedAt = time.Time{}
	sess.DBSCCurrentCookieID = ""
	sess.DBSCSessionID = ""
	return boundCookieValue
}

// cookieStoreRegistrationBinding fingerprints the durable session payload so
// stateless registration challenges cannot be replayed across sessions.
func (s *cookieStore) registrationBinding(sess persistedSession) (string, error) {
	_ = stripTransientDBSCFields(&sess)
	data, err := s.codec.Encode(sess)
	if err != nil {
		return "", fmt.Errorf("encoding session for registration binding: %w", err)
	}
	h := sha256.Sum256(data)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:]), nil
}

func (s *cookieStore) save(w http.ResponseWriter, r *http.Request, expiresAt time.Time, sess persistedSession) error {
	boundCookieValue := stripTransientDBSCFields(&sess)

	// Encode using the codec
	data, err := s.codec.Encode(sess)
	if err != nil {
		return fmt.Errorf("encoding session: %w", err)
	}

	// Add expiry time to data
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(expiresAt.Unix()))
	dataWithExpiry := append(b, data...)

	// Apply compression if needed
	magic := managerCookieMagic
	if !s.compressionDisabled && len(dataWithExpiry) > managerCompressThreshold {
		cw := getCompressor()
		defer putCompressor(cw)

		b, err := cw.Compress(dataWithExpiry)
		if err != nil {
			return fmt.Errorf("compressing cookie: %w", err)
		}
		dataWithExpiry = b
		magic = managerCompressedCookieMagic
	}

	// Determine Associated Data based on DBSC binding
	var ad []byte
	if boundCookieValue != "" {
		ad = []byte(s.cookieSettings.Name + ":" + boundCookieValue)
	} else {
		ad = []byte(s.cookieSettings.Name)
	}

	// Encrypt data with AEAD
	encryptedData, err := s.aead.Encrypt(dataWithExpiry, ad)
	if err != nil {
		return fmt.Errorf("encrypting cookie failed: %w", err)
	}

	// Format cookie value: magic.boundCookieID.encodedData
	cookieValue := magic + "." + boundCookieValue + "." + managerCookieValueEncoding.EncodeToString(encryptedData)
	if len(cookieValue) > managerMaxCookieSize {
		return fmt.Errorf("cookie size %d is greater than max %d", len(cookieValue), managerMaxCookieSize)
	}

	// Set cookie
	cookie := s.cookieSettings.newCookie(expiresAt)
	cookie.Value = cookieValue

	http.SetCookie(w, cookie)

	return nil
}

func (s *cookieStore) delete(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (s *cookieStore) touch(w http.ResponseWriter, r *http.Request, expiresAt time.Time, data []byte) error {
	// Extract boundCookieValue from the request cookie if present
	var boundCookieValue string
	if cookie, err := r.Cookie(s.cookieSettings.Name); err == nil {
		sp := strings.SplitN(cookie.Value, ".", 3)
		if len(sp) == 3 && sp[1] != "" {
			boundCookieValue = sp[1]
		}
	}

	// Encrypt data with AEAD
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(expiresAt.Unix()))
	dataWithExpiry := append(b, data...)

	// Apply compression if needed
	magic := managerCookieMagic
	if !s.compressionDisabled && len(dataWithExpiry) > managerCompressThreshold {
		cw := getCompressor()
		defer putCompressor(cw)

		b, err := cw.Compress(dataWithExpiry)
		if err != nil {
			return fmt.Errorf("compressing cookie: %w", err)
		}
		dataWithExpiry = b
		magic = managerCompressedCookieMagic
	}

	// Determine Associated Data based on DBSC binding
	var ad []byte
	if boundCookieValue != "" {
		ad = []byte(s.cookieSettings.Name + ":" + boundCookieValue)
	} else {
		ad = []byte(s.cookieSettings.Name)
	}

	// Encrypt data with AEAD
	encryptedData, err := s.aead.Encrypt(dataWithExpiry, ad)
	if err != nil {
		return fmt.Errorf("encrypting cookie failed: %w", err)
	}

	// Format cookie value: magic.boundCookieID.encodedData
	cookieValue := magic + "." + boundCookieValue + "." + managerCookieValueEncoding.EncodeToString(encryptedData)
	if len(cookieValue) > managerMaxCookieSize {
		return fmt.Errorf("cookie size %d is greater than max %d", len(cookieValue), managerMaxCookieSize)
	}

	// Set cookie
	cookie := s.cookieSettings.newCookie(expiresAt)
	cookie.Value = cookieValue

	http.SetCookie(w, cookie)

	return nil
}

func (s *cookieStore) generateChallenge(r *http.Request, sctx *Session, isRegister bool) (string, error) {
	var binding string
	var err error
	if isRegister {
		binding, err = s.registrationBinding(sctx.sessdata)
		if err != nil {
			return "", err
		}
	} else {
		binding = deriveDBSCSessionID(sctx.sessdata.DBSCPublicJWKS)
	}
	timestamp := time.Now().UnixNano()
	payload := fmt.Sprintf("%s:%d", binding, timestamp)

	// Encrypt the payload using AEAD with a specific challenge AD
	ciphertext, err := s.aead.Encrypt([]byte(payload), []byte("dbsc-challenge"))
	if err != nil {
		return "", err
	}

	return managerCookieValueEncoding.EncodeToString(ciphertext), nil
}

func (s *cookieStore) verifyChallenge(r *http.Request, sctx *Session, challengeStr string, isRegister bool) error {
	ciphertext, err := managerCookieValueEncoding.DecodeString(challengeStr)
	if err != nil {
		return fmt.Errorf("decoding challenge: %w", err)
	}

	// Decrypt the challenge
	decrypted, err := s.aead.Decrypt(ciphertext, []byte("dbsc-challenge"))
	if err != nil {
		return fmt.Errorf("decrypting challenge: %w", err)
	}

	parts := strings.SplitN(string(decrypted), ":", 2)
	if len(parts) != 2 {
		return errors.New("invalid challenge payload")
	}

	expectedSessionID := parts[0]
	timestampNano := parts[1]

	if isRegister {
		binding, err := s.registrationBinding(sctx.sessdata)
		if err != nil {
			return err
		}
		if expectedSessionID != binding {
			return errors.New("registration challenge session binding mismatch")
		}
	} else {
		sessionID := deriveDBSCSessionID(sctx.sessdata.DBSCPublicJWKS)
		if expectedSessionID != sessionID {
			return errors.New("challenge session ID mismatch")
		}
	}

	// Parse and verify timestamp
	var nano int64
	if _, err := fmt.Sscanf(timestampNano, "%d", &nano); err != nil {
		return fmt.Errorf("parsing challenge timestamp: %w", err)
	}

	issuedAt := time.Unix(0, nano)
	if time.Since(issuedAt) > 5*time.Minute {
		return errors.New("challenge expired")
	}

	return nil
}
