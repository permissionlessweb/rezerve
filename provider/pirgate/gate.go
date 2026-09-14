package pirgate

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Private-market mode: PIR_REQUIRE_COMMIT=1 (or PIR_MODE=1).
// Public Akash default (unset) still bids without this gate.

func pirMode() bool {
	return os.Getenv("PIR_REQUIRE_COMMIT") == "1" || os.Getenv("PIR_MODE") == "1"
}

// Hex64Env reads a 32-byte hex commitment from env or file.
func Hex64Env(raw, fileEnv string) (string, bool) {
	return hex64(raw, fileEnv)
}

func hex64(raw, fileEnv string) (string, bool) {
	s := strings.TrimSpace(os.Getenv(raw))
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	if p := os.Getenv(fileEnv); p != "" {
		b, err := os.ReadFile(p)
		if err == nil {
			s = strings.TrimSpace(string(b))
			s = strings.TrimPrefix(strings.ToLower(s), "0x")
		}
	}
	if len(s) != 64 {
		return "", false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", false
		}
	}
	return s, true
}

type matchReq struct {
	AskCommitment string `json:"ask_commitment"`
	BidCommitment string `json:"bid_commitment"`
}

type matchResp struct {
	Matches bool `json:"matches"`
	Data    *struct {
		Matches bool `json:"matches"`
	} `json:"data,omitempty"`
}

func parseMatchJSON(raw []byte) (matches bool, ok bool) {
	var m matchResp
	if json.Unmarshal(raw, &m) != nil {
		return false, false
	}
	if m.Data != nil {
		return m.Data.Matches, true
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal(raw, &probe) != nil {
		return false, false
	}
	if _, has := probe["matches"]; has {
		return m.Matches, true
	}
	return false, false
}

func lcdSmartURL(rawURL string, queryJSON []byte) string {
	enc := url.PathEscape(base64.StdEncoding.EncodeToString(queryJSON))
	if i := strings.LastIndex(rawURL, "/smart/"); i >= 0 {
		return rawURL[:i+len("/smart/")] + enc
	}
	if strings.HasSuffix(rawURL, "/smart") {
		return rawURL + "/" + enc
	}
	return ""
}

// queryMatch is a live cw-pir-commit Match query: POST QueryMsg
// `{"match":{ask_commitment,bid_commitment}}` → `{matches:true}` (or LCD `{data:{matches}}`).
// URLs containing `/smart` also GET CosmWasm LCD `/smart/{base64}`.
func queryMatch(endpoint, ask, bid string) (bool, error) {
	q := struct {
		Match matchReq `json:"match"`
	}{Match: matchReq{AskCommitment: ask, BidCommitment: bid}}
	body, err := json.Marshal(q)
	if err != nil {
		return false, err
	}
	c := &http.Client{Timeout: 5 * time.Second}

	post, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	post.Header.Set("Content-Type", "application/json")
	if res, err := c.Do(post); err == nil {
		raw, rerr := io.ReadAll(io.LimitReader(res.Body, 1<<16))
		res.Body.Close()
		if rerr == nil {
			if matches, ok := parseMatchJSON(raw); ok {
				return matches, nil
			}
		}
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			return false, fmt.Errorf("commit match json: %s", bytes.TrimSpace(raw))
		}
	}

	if getURL := lcdSmartURL(endpoint, body); getURL != "" {
		res, err := c.Get(getURL)
		if err != nil {
			return false, err
		}
		raw, rerr := io.ReadAll(io.LimitReader(res.Body, 1<<16))
		res.Body.Close()
		if rerr != nil {
			return false, rerr
		}
		matches, ok := parseMatchJSON(raw)
		if !ok {
			return false, fmt.Errorf("commit match lcd json: %s", bytes.TrimSpace(raw))
		}
		return matches, nil
	}

	return false, fmt.Errorf("cw-pir-commit match query failed")
}

type zap1Accept struct {
	Accepted          bool `json:"accepted"`
	Matches           bool `json:"matches"`
	Zap1Matches       bool `json:"zap1_matches"`
	Zap1Halo2Accepted bool `json:"zap1_halo2_accepted"`
	Zap1Halo2Stored   bool `json:"zap1_halo2_stored"`
}

func zap1Accepted() (bool, error) {
	if os.Getenv("PIR_ZAP1_REQUIRE") != "1" {
		return true, nil
	}
	if u := os.Getenv("PIR_ZAP1_ACCEPT_URL"); u != "" {
		c := &http.Client{Timeout: 5 * time.Second}
		res, err := c.Get(u)
		if err != nil {
			return false, err
		}
		defer res.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<16))
		if err != nil {
			return false, err
		}
		return zap1JSONOk(raw), nil
	}
	p := os.Getenv("PIR_ZAP1_ACCEPT_FILE")
	if p == "" {
		return false, fmt.Errorf("PIR_ZAP1_REQUIRE=1 needs PIR_ZAP1_ACCEPT_FILE or PIR_ZAP1_ACCEPT_URL")
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return false, err
	}
	return zap1JSONOk(raw), nil
}

func zap1JSONOk(raw []byte) bool {
	var z zap1Accept
	if json.Unmarshal(raw, &z) != nil {
		return false
	}
	return z.Zap1Halo2Accepted || z.Zap1Matches || z.Matches || z.Accepted
}

// resolveAskBid returns 32-byte hex commitments. Bid hex may come from a
// ChaCha envelope. ok is false on parse/open/require-envelope failure.
func resolveAskBid() (ask, bid string, envLoaded, ok bool) {
	ask, okA := hex64("PIR_ASK_COMMIT", "PIR_ASK_COMMIT_FILE")
	bid, okB := hex64("PIR_BID_COMMIT", "PIR_BID_COMMIT_FILE")
	env, envErr := loadEnvelopeFromEnv()
	if envErr != nil {
		return "", "", false, false
	}
	if env != nil {
		derived := env.CommitmentHex()
		if okB && bid != derived {
			return ask, derived, true, false
		}
		bid, okB = derived, true
		if ks := os.Getenv("PIR_SESSION_KEY"); ks != "" {
			key, err := ParseKey32(ks)
			if err != nil {
				return ask, bid, true, false
			}
			if _, err := env.Open(key); err != nil {
				return ask, bid, true, false
			}
		}
		envLoaded = true
	}
	if os.Getenv("PIR_REQUIRE_ENVELOPE") == "1" && env == nil {
		return ask, bid, false, false
	}
	return ask, bid, envLoaded, okA && okB
}

// EnvelopeLoaded is true when a ChaCha20-Poly1305 OOB envelope was parsed.
func EnvelopeLoaded() bool {
	env, err := loadEnvelopeFromEnv()
	return err == nil && env != nil
}

// CommitMatchURLSet is true when PIR_COMMIT_MATCH_URL is non-empty.
func CommitMatchURLSet() bool {
	return strings.TrimSpace(os.Getenv("PIR_COMMIT_MATCH_URL")) != ""
}

// LiveCommitMatches is the live cw-pir-commit Match query. False when the
// URL is unset, commits cannot be resolved, or the response is not {matches:true}.
func LiveCommitMatches() bool {
	u := strings.TrimSpace(os.Getenv("PIR_COMMIT_MATCH_URL"))
	if u == "" {
		return false
	}
	ask, bid, _, ok := resolveAskBid()
	if !ok {
		return false
	}
	m, err := queryMatch(u, ask, bid)
	return err == nil && m
}

// PirAllocationAllowed is the native re-zerve allocate gate.
//
// PIR mode fail-closed unless:
//  1. ask + bid commitments are 32-byte hex (bid hex may be derived from a
//     ChaCha20-Poly1305 OOB envelope via PIR_BID_ENVELOPE[_FILE]), and
//  2. when PIR_COMMIT_MATCH_URL is set, that query returns {matches:true}
//     (cw-pir-commit Match JSON), and
//  3. optional PIR_ZAP1_REQUIRE=1 reports Halo2/ZAP1 accept.
//
// PIR_REQUIRE_ENVELOPE=1 fail-closes without a ChaCha envelope. When
// PIR_SESSION_KEY is set with an envelope, Open must succeed (loser key denies).
func PirAllocationAllowed() bool {
	if !pirMode() {
		return true
	}
	ask, bid, envLoaded, ok := resolveAskBid()
	if !ok {
		return false
	}
	u := strings.TrimSpace(os.Getenv("PIR_COMMIT_MATCH_URL"))
	if os.Getenv("PIR_REQUIRE_ENVELOPE") == "1" && u == "" {
		return false
	}
	if u != "" {
		matched, err := queryMatch(u, ask, bid)
		if err != nil || !matched {
			return false
		}
	}
	_ = envLoaded
	zok, err := zap1Accepted()
	if err != nil || !zok {
		return false
	}
	return true
}
