package pir

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMarketWorkflowAcceptAccessClose(t *testing.T) {
	dir := t.TempDir()
	book := filepath.Join(dir, "leases.json")
	t.Setenv("PIR_LEASE_BOOK_FILE", book)
	t.Setenv("PIR_ACCESS_BEARERS", "")
	t.Setenv("PIR_ACCESS_BEARERS_FILE", "")
	ResetAllowed()

	var session, bid [32]byte
	for i := range session {
		session[i] = 1
		bid[i] = 2
	}
	winner := BearerHex(SecretFromSession("ask-1", session, bid))
	foreign := BearerHex(SecretFromSession("ask-other", session, bid))

	if err := AcceptBid("lease-1", winner); err != nil {
		t.Fatal(err)
	}
	if AccessLease("lease-1", winner) != "ok" {
		t.Fatal("winner must access after accept")
	}
	if !AcceptBearer(winner) {
		t.Fatal("gateway must honor open lease bearer")
	}
	if AccessLease("lease-1", foreign) != "unauthorized" {
		t.Fatal("foreign bearer denied")
	}
	if AcceptBearer(foreign) {
		t.Fatal("gateway must deny foreign bearer")
	}
	if err := CloseLease("lease-1"); err != nil {
		t.Fatal(err)
	}
	if AccessLease("lease-1", winner) != "closed" {
		t.Fatal("close must deny winner")
	}
	if AcceptBearer(winner) {
		t.Fatal("gateway must deny after close without restart")
	}
}

func TestBearerFileReloadWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bearers")
	t.Setenv("PIR_LEASE_BOOK_FILE", "")
	t.Setenv("PIR_ACCESS_BEARERS", "")
	ResetAllowed()

	var session, bid [32]byte
	for i := range session {
		session[i] = 1
		bid[i] = 2
	}
	b := BearerHex(SecretFromSession("ask-1", session, bid))
	if err := os.WriteFile(f, []byte(b+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PIR_ACCESS_BEARERS_FILE", f)
	if !AcceptBearer(b) {
		t.Fatal("file allow-list must accept")
	}
	if err := os.WriteFile(f, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if AcceptBearer(b) {
		t.Fatal("truncated allow-list file must deny without ResetAllowed")
	}
}
