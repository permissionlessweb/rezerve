// Package pir is native re-zerve access on the provider: derived bearer
// (not ES256K JWT) and a lease book that honors accept / close.
package pir

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"sync"
)

const (
	tagBearer = "pir-access-bearer-v1"
	tagSecret = "pir-access-v1"
)

var (
	mu      sync.Mutex
	allowed map[string]struct{}
)

func taggedHash(tag string, parts ...[]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(tag))
	h.Write([]byte{byte(len(tag))})
	for _, p := range parts {
		var ln [8]byte
		binary.LittleEndian.PutUint64(ln[:], uint64(len(p)))
		h.Write(ln[:])
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SecretFromSession matches Rust DerivedAccess::from_session.
func SecretFromSession(askID string, sessionKey, bidCommitment [32]byte) [32]byte {
	return taggedHash(tagSecret, sessionKey[:], bidCommitment[:], []byte(askID))
}

// BearerHex matches Rust DerivedAccess::bearer_hex.
func BearerHex(secret [32]byte) string {
	b := taggedHash(tagBearer, secret[:])
	return hex.EncodeToString(b[:])
}

func loadEnvOrFile() map[string]struct{} {
	out := map[string]struct{}{}
	raw := os.Getenv("PIR_ACCESS_BEARERS")
	if p := os.Getenv("PIR_ACCESS_BEARERS_FILE"); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			raw = string(b)
		}
	}
	for _, t := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == ' '
	}) {
		t = strings.TrimSpace(strings.ToLower(t))
		if len(t) == 64 {
			out[t] = struct{}{}
		}
	}
	return out
}

// ResetAllowed for tests (in-memory env snapshot). File lists are always reread.
func ResetAllowed() {
	mu.Lock()
	allowed = nil
	bookMu.Lock()
	if leasePath() == "" {
		book = map[string]LeaseRec{}
	}
	bookMu.Unlock()
	mu.Unlock()
}

func hexTok(tok string) (string, bool) {
	t := strings.ToLower(strings.TrimSpace(tok))
	if len(t) != 64 {
		return "", false
	}
	for _, c := range t {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", false
		}
	}
	return t, true
}

// AcceptBearer is true if tok is a 64-hex PIR bearer on an *open* lease
// or on the allow-list. The allow-list file is reread every call so close
// can truncate it without restarting provider-services.
func AcceptBearer(tok string) bool {
	t, ok := hexTok(tok)
	if !ok {
		return false
	}
	if _, hit := openBearers()[t]; hit {
		_ = subtle.ConstantTimeCompare([]byte(t), []byte(t))
		return true
	}
	al := loadEnvOrFile()
	_, ok = al[t]
	if !ok {
		return false
	}
	_ = subtle.ConstantTimeCompare([]byte(t), []byte(t))
	return true
}
