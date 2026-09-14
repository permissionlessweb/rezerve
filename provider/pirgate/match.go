package pirgate

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// CommitStore is a local cw-pir-commit Match surface: 32-byte hex only, no price.
type CommitStore struct {
	mu  sync.Mutex
	ask string
	bid string
}

func NewCommitStore(ask, bid string) *CommitStore {
	return &CommitStore{ask: ask, bid: bid}
}

func (s *CommitStore) Post(ask, bid string) {
	s.mu.Lock()
	s.ask, s.bid = ask, bid
	s.mu.Unlock()
}

func (s *CommitStore) Match(ask, bid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ask != "" && s.bid != "" && s.ask == ask && s.bid == bid
}

func decodeMatchBody(raw []byte) (ask, bid string) {
	var m matchReq
	if json.Unmarshal(raw, &m) == nil && (m.AskCommitment != "" || m.BidCommitment != "") {
		return m.AskCommitment, m.BidCommitment
	}
	var wrap struct {
		Match matchReq `json:"match"`
	}
	if json.Unmarshal(raw, &wrap) == nil {
		return wrap.Match.AskCommitment, wrap.Match.BidCommitment
	}
	return "", ""
}

// CommitMatchHandler speaks cw-pir-commit Match JSON: {matches:true|false}.
func CommitMatchHandler(store *CommitStore) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	writeMatch := func(w http.ResponseWriter, ask, bid string) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(matchResp{Matches: store.Match(ask, bid)})
	}
	decodeB64Query := func(enc string) []byte {
		enc, _ = url.PathUnescape(enc)
		enc = strings.TrimSpace(enc)
		for _, dec := range []func(string) ([]byte, error){
			base64.StdEncoding.DecodeString,
			base64.URLEncoding.DecodeString,
			base64.RawStdEncoding.DecodeString,
			base64.RawURLEncoding.DecodeString,
		} {
			if raw, err := dec(enc); err == nil {
				return raw
			}
		}
		return []byte(enc)
	}
	handleMatch := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			q := r.URL.Query()
			ask, bid := q.Get("ask_commitment"), q.Get("bid_commitment")
			if ask == "" && bid == "" {
				if qs := q.Get("query"); qs != "" {
					ask, bid = decodeMatchBody(decodeB64Query(qs))
				}
			}
			if ask != "" || bid != "" {
				writeMatch(w, ask, bid)
				return
			}
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			http.Error(w, "body", http.StatusBadRequest)
			return
		}
		ask, bid := decodeMatchBody(raw)
		writeMatch(w, ask, bid)
	}
	handleSmart := func(w http.ResponseWriter, r *http.Request) {
		enc := strings.TrimPrefix(r.URL.Path, "/smart/")
		enc = strings.Trim(enc, "/")
		if enc == "" {
			handleMatch(w, r)
			return
		}
		ask, bid := decodeMatchBody(decodeB64Query(enc))
		writeMatch(w, ask, bid)
	}
	handleExecute := func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			http.Error(w, "body", http.StatusBadRequest)
			return
		}
		var exec struct {
			PostCommitments *matchReq `json:"post_commitments"`
		}
		if json.Unmarshal(raw, &exec) == nil && exec.PostCommitments != nil {
			store.Post(exec.PostCommitments.AskCommitment, exec.PostCommitments.BidCommitment)
		} else {
			var m matchReq
			if json.Unmarshal(raw, &m) == nil {
				store.Post(m.AskCommitment, m.BidCommitment)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}
	mux.HandleFunc("/match", handleMatch)
	mux.HandleFunc("/query", handleMatch)
	mux.HandleFunc("/smart/", handleSmart)
	mux.HandleFunc("/smart", handleSmart)
	mux.HandleFunc("/execute", handleExecute)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
			return
		}
		handleMatch(w, r)
	})
	return mux
}
