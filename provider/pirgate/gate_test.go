package pirgate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPirAllocationDefaultAllow(t *testing.T) {
	t.Setenv("PIR_REQUIRE_COMMIT", "")
	t.Setenv("PIR_MODE", "")
	if !PirAllocationAllowed() {
		t.Fatal("public market default must allow")
	}
}

// Side-market vs public Akash: same binary. Unset PIR mode still allocates
// (public market uninterrupted). Private mode fail-closes without Terp match
// and without the ChaCha envelope when required.
func TestPirSideMarketDoesNotInterruptPublicAllocate(t *testing.T) {
	t.Setenv("PIR_REQUIRE_COMMIT", "")
	t.Setenv("PIR_MODE", "")
	t.Setenv("PIR_REQUIRE_ENVELOPE", "")
	t.Setenv("PIR_COMMIT_MATCH_URL", "")
	t.Setenv("PIR_ASK_COMMIT", "")
	t.Setenv("PIR_BID_COMMIT", "")
	if !PirAllocationAllowed() {
		t.Fatal("public Akash allocate must still succeed when side-market env is unset")
	}

	t.Setenv("PIR_REQUIRE_COMMIT", "1")
	t.Setenv("PIR_REQUIRE_ENVELOPE", "1")
	t.Setenv("PIR_COMMIT_MATCH_URL", "")
	t.Setenv("PIR_ASK_COMMIT", "aa"+zeroHex(62))
	t.Setenv("PIR_BID_COMMIT", "bb"+zeroHex(62))
	if PirAllocationAllowed() {
		t.Fatal("side-market must fail-closed without Terp match URL and envelope")
	}
}

func TestPirAllocationRequiresHexNotEmptyFile(t *testing.T) {
	t.Setenv("PIR_REQUIRE_COMMIT", "1")
	t.Setenv("PIR_ASK_COMMIT", "")
	t.Setenv("PIR_BID_COMMIT", "")
	t.Setenv("PIR_ASK_COMMIT_FILE", "")
	t.Setenv("PIR_BID_COMMIT_FILE", "")
	t.Setenv("PIR_COMMIT_MATCH_URL", "")
	t.Setenv("PIR_ZAP1_REQUIRE", "")
	t.Setenv("PIR_REQUIRE_ENVELOPE", "")
	t.Setenv("PIR_BID_ENVELOPE", "")
	t.Setenv("PIR_BID_ENVELOPE_FILE", "")
	t.Setenv("PIR_SESSION_KEY", "")
	if PirAllocationAllowed() {
		t.Fatal("must block without 32-byte hex commits")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "bid")
	if err := os.WriteFile(p, []byte("not-hex"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PIR_BID_COMMIT_FILE", p)
	t.Setenv("PIR_ASK_COMMIT", "11"+zeroHex(62))
	if PirAllocationAllowed() {
		t.Fatal("non-hex commit file must not allocate")
	}
}

func zeroHex(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '0'
	}
	return string(b)
}

func TestPirAllocationMatchURL(t *testing.T) {
	t.Setenv("PIR_REQUIRE_COMMIT", "1")
	t.Setenv("PIR_ZAP1_REQUIRE", "")
	ask := "aa" + zeroHex(62)
	bid := "bb" + zeroHex(62)
	t.Setenv("PIR_ASK_COMMIT", ask)
	t.Setenv("PIR_BID_COMMIT", bid)
	t.Setenv("PIR_ASK_COMMIT_FILE", "")
	t.Setenv("PIR_BID_COMMIT_FILE", "")
	t.Setenv("PIR_REQUIRE_ENVELOPE", "")
	t.Setenv("PIR_BID_ENVELOPE", "")
	t.Setenv("PIR_BID_ENVELOPE_FILE", "")
	t.Setenv("PIR_SESSION_KEY", "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var wrap struct {
			Match matchReq `json:"match"`
		}
		_ = json.NewDecoder(r.Body).Decode(&wrap)
		ok := wrap.Match.AskCommitment == ask && wrap.Match.BidCommitment == bid
		_ = json.NewEncoder(w).Encode(matchResp{Matches: ok})
	}))
	defer srv.Close()
	t.Setenv("PIR_COMMIT_MATCH_URL", srv.URL)
	if !PirAllocationAllowed() {
		t.Fatal("matching cw-pir-commit URL must allocate")
	}
	if !LiveCommitMatches() {
		t.Fatal("live cw-pir-commit must report {matches:true}")
	}
	t.Setenv("PIR_BID_COMMIT", "cc"+zeroHex(62))
	if PirAllocationAllowed() {
		t.Fatal("tampered bid hex must not allocate")
	}
	if LiveCommitMatches() {
		t.Fatal("tampered bid must not be {matches:true}")
	}
}

func TestPirAllocationZap1Required(t *testing.T) {
	t.Setenv("PIR_REQUIRE_COMMIT", "1")
	t.Setenv("PIR_COMMIT_MATCH_URL", "")
	t.Setenv("PIR_ASK_COMMIT", "aa"+zeroHex(62))
	t.Setenv("PIR_BID_COMMIT", "bb"+zeroHex(62))
	t.Setenv("PIR_REQUIRE_ENVELOPE", "")
	t.Setenv("PIR_BID_ENVELOPE", "")
	t.Setenv("PIR_BID_ENVELOPE_FILE", "")
	t.Setenv("PIR_SESSION_KEY", "")
	t.Setenv("PIR_ZAP1_REQUIRE", "1")
	t.Setenv("PIR_ZAP1_ACCEPT_URL", "")
	t.Setenv("PIR_ZAP1_ACCEPT_FILE", "")
	if PirAllocationAllowed() {
		t.Fatal("missing zap1 accept must fail closed")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "zap1.json")
	if err := os.WriteFile(p, []byte(`{"zap1_halo2_accepted":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PIR_ZAP1_ACCEPT_FILE", p)
	if !PirAllocationAllowed() {
		t.Fatal("halo2 accept file must allocate")
	}
}

func TestPirAllocationEnvelopeAndMatchURL(t *testing.T) {
	t.Setenv("PIR_REQUIRE_COMMIT", "1")
	t.Setenv("PIR_REQUIRE_ENVELOPE", "1")
	t.Setenv("PIR_ZAP1_REQUIRE", "")
	t.Setenv("PIR_BID_COMMIT", "")
	t.Setenv("PIR_BID_COMMIT_FILE", "")
	ask := "aa" + zeroHex(62)
	t.Setenv("PIR_ASK_COMMIT", ask)

	var key [32]byte
	copy(key[:], bytesOf(0x11, 32))
	var n16 [16]byte
	copy(n16[:], bytesOf(0x22, 16))
	env, err := SealEnvelope(PlaintextBid{
		AskID:            "ask-1",
		BidderIdentity:   "prov",
		PriceUakt:        9000,
		ProviderEndpoint: "oob://p",
	}, key, n16)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.Open(key); err != nil {
		t.Fatal(err)
	}
	var loser [32]byte
	copy(loser[:], bytesOf(0x33, 32))
	if _, err := env.Open(loser); err == nil {
		t.Fatal("loser session key must not open ChaCha envelope")
	}
	bid := env.CommitmentHex()
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "envelope.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PIR_BID_ENVELOPE_FILE", p)
	t.Setenv("PIR_SESSION_KEY", hexOf(key[:]))
	t.Setenv("PIR_COMMIT_MATCH_URL", "")
	if PirAllocationAllowed() {
		t.Fatal("PIR_REQUIRE_ENVELOPE=1 must fail-closed without PIR_COMMIT_MATCH_URL")
	}

	store := NewCommitStore(ask, bid)
	srv := httptest.NewServer(CommitMatchHandler(store))
	defer srv.Close()
	t.Setenv("PIR_COMMIT_MATCH_URL", srv.URL+"/match")
	if !PirAllocationAllowed() {
		t.Fatal("cw-pir-commit {matches:true} must allocate")
	}
	if !EnvelopeLoaded() {
		t.Fatal("ChaCha envelope must be ingested")
	}
	if !LiveCommitMatches() {
		t.Fatal("envelope-derived bid must match live cw-pir-commit")
	}
	t.Setenv("PIR_BID_COMMIT", "cc"+zeroHex(62))
	if PirAllocationAllowed() {
		t.Fatal("hex that disagrees with envelope commitment must not allocate")
	}
	t.Setenv("PIR_BID_COMMIT", "")
	store.Post(ask, "cc"+zeroHex(62))
	if PirAllocationAllowed() {
		t.Fatal("stored mismatch must be {matches:false}")
	}
}

func TestPirAllocationCosmwasmDataWrapAndLCDGet(t *testing.T) {
	t.Setenv("PIR_REQUIRE_COMMIT", "1")
	t.Setenv("PIR_ZAP1_REQUIRE", "")
	t.Setenv("PIR_REQUIRE_ENVELOPE", "")
	t.Setenv("PIR_BID_ENVELOPE", "")
	t.Setenv("PIR_BID_ENVELOPE_FILE", "")
	t.Setenv("PIR_SESSION_KEY", "")
	t.Setenv("PIR_ASK_COMMIT_FILE", "")
	t.Setenv("PIR_BID_COMMIT_FILE", "")
	ask := "aa" + zeroHex(62)
	bid := "bb" + zeroHex(62)
	t.Setenv("PIR_ASK_COMMIT", ask)
	t.Setenv("PIR_BID_COMMIT", bid)

	lcd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/smart") {
			http.Error(w, "lcd is GET /smart/{b64}", http.StatusMethodNotAllowed)
			return
		}
		// CommitMatchHandler-compatible: last path segment is QueryMsg b64.
		store := NewCommitStore(ask, bid)
		CommitMatchHandler(store).ServeHTTP(w, r)
	}))
	defer lcd.Close()
	t.Setenv("PIR_COMMIT_MATCH_URL", lcd.URL+"/smart")
	if !PirAllocationAllowed() {
		t.Fatal("LCD GET /smart/{b64 QueryMsg match} must allocate")
	}
	t.Setenv("PIR_BID_COMMIT", "cc"+zeroHex(62))
	if PirAllocationAllowed() {
		t.Fatal("LCD mismatch must not allocate")
	}

	t.Setenv("PIR_BID_COMMIT", bid)
	dataSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(matchResp{Data: &struct {
			Matches bool `json:"matches"`
		}{Matches: true}})
	}))
	defer dataSrv.Close()
	t.Setenv("PIR_COMMIT_MATCH_URL", dataSrv.URL)
	if !PirAllocationAllowed() {
		t.Fatal("cw-pir-commit LCD {data:{matches:true}} must allocate")
	}
}

func bytesOf(v byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = d[x>>4]
		out[i*2+1] = d[x&0x0f]
	}
	return string(out)
}
