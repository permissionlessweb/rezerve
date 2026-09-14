package pirgate

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const bidCommitTag = "bid-commit-v1"

// jsonBytes marshals as a JSON number array so it matches Rust serde [u8; N].
type jsonBytes []byte

func (j jsonBytes) MarshalJSON() ([]byte, error) {
	if j == nil {
		return []byte("[]"), nil
	}
	var b strings.Builder
	b.WriteByte('[')
	for i, v := range j {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(int(v)))
	}
	b.WriteByte(']')
	return []byte(b.String()), nil
}

func (j *jsonBytes) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		*j = nil
		return nil
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return err
		}
		s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
		dec, err := hex.DecodeString(s)
		if err != nil {
			return err
		}
		*j = dec
		return nil
	}
	var nums []uint8
	if err := json.Unmarshal(raw, &nums); err != nil {
		return err
	}
	*j = nums
	return nil
}

// Envelope is the ChaCha20-Poly1305 OOB bid (same JSON as EncryptedBidEnvelope).
type Envelope struct {
	AskID      string    `json:"ask_id"`
	Nonce      jsonBytes `json:"nonce"`
	Ciphertext jsonBytes `json:"ciphertext"`
	Mac        jsonBytes `json:"mac"`
}

// PlaintextBid is never posted on-chain.
type PlaintextBid struct {
	AskID            string `json:"ask_id"`
	BidderIdentity   string `json:"bidder_identity"`
	PriceUakt        uint64 `json:"price_uakt"`
	ProviderEndpoint string `json:"provider_endpoint"`
}

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

func aeadAAD(askID string, nonce []byte) []byte {
	aad := make([]byte, 0, 8+len(askID)+len(nonce))
	var ln [8]byte
	binary.LittleEndian.PutUint64(ln[:], uint64(len(askID)))
	aad = append(aad, ln[:]...)
	aad = append(aad, askID...)
	aad = append(aad, nonce...)
	return aad
}

// SealEnvelope encrypts a plaintext bid with ChaCha20-Poly1305 (not AES/JWT).
func SealEnvelope(bid PlaintextBid, sessionKey [32]byte, nonce [16]byte) (*Envelope, error) {
	if bid.BidderIdentity == "" || bid.PriceUakt == 0 {
		return nil, fmt.Errorf("empty bid")
	}
	if nonce == ([16]byte{}) {
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, err
		}
	}
	plain, err := json.Marshal(bid)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(sessionKey[:])
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonce[:12], plain, aeadAAD(bid.AskID, nonce[:]))
	if len(sealed) < 16 {
		return nil, fmt.Errorf("aead short")
	}
	mac := make([]byte, 32)
	copy(mac, sealed[len(sealed)-16:])
	return &Envelope{
		AskID:      bid.AskID,
		Nonce:      append(jsonBytes(nil), nonce[:]...),
		Ciphertext: append(jsonBytes(nil), sealed[:len(sealed)-16]...),
		Mac:        jsonBytes(mac),
	}, nil
}

// Open decrypts with ChaCha20-Poly1305. Wrong key → auth error.
func (e *Envelope) Open(sessionKey [32]byte) (*PlaintextBid, error) {
	if len(e.Nonce) < 12 || len(e.Ciphertext) == 0 || len(e.Mac) < 16 {
		return nil, fmt.Errorf("truncated envelope")
	}
	aead, err := chacha20poly1305.New(sessionKey[:])
	if err != nil {
		return nil, err
	}
	sealed := append(append([]byte{}, e.Ciphertext...), e.Mac[:16]...)
	plain, err := aead.Open(nil, e.Nonce[:12], sealed, aeadAAD(e.AskID, e.Nonce))
	if err != nil {
		return nil, fmt.Errorf("chacha auth")
	}
	var bid PlaintextBid
	if err := json.Unmarshal(plain, &bid); err != nil {
		return nil, err
	}
	return &bid, nil
}

// Commitment is bid-commit-v1 over envelope fields (32-byte hex on-chain).
func (e *Envelope) Commitment() [32]byte {
	return taggedHash(bidCommitTag, []byte(e.AskID), e.Nonce, e.Ciphertext, e.Mac)
}

func (e *Envelope) CommitmentHex() string {
	c := e.Commitment()
	return hex.EncodeToString(c[:])
}

// ParseEnvelope accepts a raw envelope or seal-command wrap {"envelope":{...}}.
func ParseEnvelope(raw []byte) (*Envelope, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty envelope")
	}
	var wrap struct {
		Envelope *Envelope `json:"envelope"`
	}
	if json.Unmarshal(raw, &wrap) == nil && wrap.Envelope != nil && wrap.Envelope.AskID != "" {
		return wrap.Envelope, nil
	}
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if env.AskID == "" || len(env.Ciphertext) == 0 {
		return nil, fmt.Errorf("not a ChaCha envelope")
	}
	return &env, nil
}

func ParseKey32(s string) ([32]byte, error) {
	var out [32]byte
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("session key must be 32-byte hex")
	}
	copy(out[:], b)
	return out, nil
}

func ParseNonce16(s string) ([16]byte, error) {
	var out [16]byte
	if strings.TrimSpace(s) == "" {
		return out, nil
	}
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		return out, fmt.Errorf("nonce must be 16-byte hex")
	}
	copy(out[:], b)
	return out, nil
}

func loadEnvelopeFromEnv() (*Envelope, error) {
	raw := strings.TrimSpace(os.Getenv("PIR_BID_ENVELOPE"))
	if p := os.Getenv("PIR_BID_ENVELOPE_FILE"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		raw = strings.TrimSpace(string(b))
	}
	if raw == "" {
		return nil, nil
	}
	return ParseEnvelope([]byte(raw))
}
