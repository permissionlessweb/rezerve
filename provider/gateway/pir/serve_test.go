package pir

import (
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"testing"
	"time"
)

func dockerOk() bool {
	return exec.Command("docker", "info").Run() == nil
}

func TestServeSpawnsDeniedWithoutCommit(t *testing.T) {
	t.Setenv("PIR_REQUIRE_COMMIT", "1")
	t.Setenv("PIR_ASK_COMMIT", "")
	t.Setenv("PIR_BID_COMMIT", "")
	t.Setenv("PIR_ASK_COMMIT_FILE", "")
	t.Setenv("PIR_BID_COMMIT_FILE", "")
	t.Setenv("PIR_COMMIT_MATCH_URL", "")
	t.Setenv("PIR_REQUIRE_ENVELOPE", "")
	t.Setenv("PIR_BID_ENVELOPE", "")
	t.Setenv("PIR_BID_ENVELOPE_FILE", "")
	t.Setenv("PIR_SESSION_KEY", "")
	t.Setenv("PIR_ZAP1_REQUIRE", "")
	dir := t.TempDir()
	t.Setenv("PIR_LEASE_BOOK_FILE", dir+"/leases.json")
	ResetAllowed()
	_, _, err := ServeLease("no-commit", "aa00000000000000000000000000000000000000000000000000000000000000", "", 18765)
	if err == nil {
		t.Fatal("serve must not spawn when allocate is denied")
	}
}

func TestServeSpawnsAndServesThenStop(t *testing.T) {
	if !dockerOk() {
		t.Skip("docker not available")
	}
	dir := t.TempDir()
	t.Setenv("PIR_LEASE_BOOK_FILE", dir+"/leases.json")
	t.Setenv("PIR_ACCESS_BEARERS", "")
	ResetAllowed()

	var session, bid [32]byte
	for i := range session {
		session[i] = 1
		bid[i] = 2
	}
	bearer := BearerHex(SecretFromSession("ask-1", session, bid))
	lease := "wf1"
	defer func() { _ = StopServe(lease) }()

	id, port, err := ServeLease(lease, bearer, "python:3.12-alpine", 18765)
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("empty container id")
	}
	if !ContainerRunning(lease) {
		t.Fatal("container not running")
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	var last error
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		res, err := http.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if res.StatusCode == 200 {
				last = nil
				break
			}
			last = fmt.Errorf("status %d", res.StatusCode)
		} else {
			last = err
		}
		time.Sleep(400 * time.Millisecond)
	}
	if last != nil {
		t.Fatalf("not served: %v", last)
	}
	if AccessLease(lease, bearer) != "ok" {
		t.Fatal("bearer must access while served")
	}
	if err := StopServe(lease); err != nil {
		t.Fatal(err)
	}
	if ContainerRunning(lease) {
		t.Fatal("container still running after stop")
	}
	if AccessLease(lease, bearer) != "closed" {
		t.Fatal("bearer must be closed after stop")
	}
}
