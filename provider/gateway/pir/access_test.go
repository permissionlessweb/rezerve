package pir

import (
	"os"
	"testing"
)

func TestBearerMatchesRustVector(t *testing.T) {
	var session, bid [32]byte
	for i := 0; i < 32; i++ {
		session[i] = 1
		bid[i] = 2
	}
	sec := SecretFromSession("ask-1", session, bid)
	got := BearerHex(sec)
	// Must match crates/private-inference-rent/tests/access_derive.rs interop vector.
	want := os.Getenv("PIR_BEARER_VECTOR")
	if want == "" {
		want = "ed105aa1fbea7d092b317a6fc11c315c68e756153a2aa5e8ba47381ee9ac88b0"
	}
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestAcceptBearerAllowList(t *testing.T) {
	ResetAllowed()
	var session, bid [32]byte
	for i := range session {
		session[i] = 1
		bid[i] = 2
	}
	b := BearerHex(SecretFromSession("ask-1", session, bid))
	t.Setenv("PIR_ACCESS_BEARERS", b)
	ResetAllowed()
	if !AcceptBearer(b) {
		t.Fatal("winner bearer rejected")
	}
	if AcceptBearer("aa" + b[2:]) {
		t.Fatal("tampered bearer accepted")
	}
}

// Closed lease deny: allow-list honor after grant/close (access kill, not escrow).
func TestClosedLeaseDenyBearer(t *testing.T) {
	ResetAllowed()
	var session, bid [32]byte
	for i := range session {
		session[i] = 1
		bid[i] = 2
	}
	b := BearerHex(SecretFromSession("ask-1", session, bid))
	t.Setenv("PIR_ACCESS_BEARERS", b)
	ResetAllowed()
	if !AcceptBearer(b) {
		t.Fatal("open lease must accept winner bearer")
	}
	// Close: empty allow-list (LeaseBook open=false).
	t.Setenv("PIR_ACCESS_BEARERS", "")
	ResetAllowed()
	if AcceptBearer(b) {
		t.Fatal("closed lease must deny bearer")
	}
}
