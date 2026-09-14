package pir

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// LeaseRec is one deployment the private market opened for a derived bearer.
type LeaseRec struct {
	Bearer    string `json:"bearer"`
	Open      bool   `json:"open"`
	Container string `json:"container,omitempty"`
	HostPort  int    `json:"host_port,omitempty"`
	Name      string `json:"name,omitempty"`
}

var (
	bookMu sync.Mutex
	book   map[string]LeaseRec
)

func leasePath() string {
	return os.Getenv("PIR_LEASE_BOOK_FILE")
}

func loadBook() map[string]LeaseRec {
	p := leasePath()
	if p == "" {
		if book == nil {
			book = map[string]LeaseRec{}
		}
		return book
	}
	raw, err := os.ReadFile(p)
	if err != nil || len(raw) == 0 {
		return map[string]LeaseRec{}
	}
	var m map[string]LeaseRec
	if json.Unmarshal(raw, &m) != nil {
		return map[string]LeaseRec{}
	}
	return m
}

func saveBook(m map[string]LeaseRec) error {
	p := leasePath()
	book = m
	if p == "" {
		return nil
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(p); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(p, raw, 0o600)
}

// AcceptBid opens a lease for the winner derived bearer only.
func AcceptBid(leaseID, bearer string) error {
	bookMu.Lock()
	defer bookMu.Unlock()
	m := loadBook()
	m[leaseID] = LeaseRec{Bearer: stringsLower(bearer), Open: true}
	return saveBook(m)
}

// CloseLease denies later access for that lease (access kill, not escrow).
func CloseLease(leaseID string) error {
	bookMu.Lock()
	defer bookMu.Unlock()
	m := loadBook()
	if rec, ok := m[leaseID]; ok {
		rec.Open = false
		m[leaseID] = rec
	}
	return saveBook(m)
}

// AccessLease is the Go LeaseBook: unknown / closed / unauthorized / ok.
func AccessLease(leaseID, bearer string) string {
	bookMu.Lock()
	defer bookMu.Unlock()
	m := loadBook()
	rec, ok := m[leaseID]
	if !ok {
		return "unknown"
	}
	if !rec.Open {
		return "closed"
	}
	if rec.Bearer != stringsLower(bearer) {
		return "unauthorized"
	}
	return "ok"
}

func openBearers() map[string]struct{} {
	bookMu.Lock()
	defer bookMu.Unlock()
	m := loadBook()
	out := map[string]struct{}{}
	for _, rec := range m {
		if rec.Open && len(rec.Bearer) == 64 {
			out[rec.Bearer] = struct{}{}
		}
	}
	return out
}

func stringsLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
