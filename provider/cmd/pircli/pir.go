package pircli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/akash-network/provider/gateway/pir"
	"github.com/akash-network/provider/pirgate"
)

// Command is native re-zerve market control (`provider-services pir`).
func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pir",
		Short: "re-zerve private-market gates (commit, bearer, lease)",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
	cmd.AddCommand(pirCheckCmd())
	cmd.AddCommand(pirAcceptCmd())
	cmd.AddCommand(pirCloseCmd())
	cmd.AddCommand(pirAccessCmd())
	cmd.AddCommand(pirServeCmd())
	cmd.AddCommand(pirStopCmd())
	cmd.AddCommand(pirSidecarCmd())
	cmd.AddCommand(pirSealCmd())
	cmd.AddCommand(pirMatchServeCmd())
	return cmd
}

func pirCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Print whether allocate is allowed under PIR_REQUIRE_COMMIT",
		RunE: func(cmd *cobra.Command, args []string) error {
			ok := pirgate.PirAllocationAllowed()
			enc := json.NewEncoder(os.Stdout)
			return enc.Encode(map[string]any{
				"allocate":  ok,
				"pir_mode":  os.Getenv("PIR_REQUIRE_COMMIT") == "1" || os.Getenv("PIR_MODE") == "1",
				"envelope":  pirgate.EnvelopeLoaded(),
				"match_url": pirgate.CommitMatchURLSet(),
				"matches":   pirgate.LiveCommitMatches(),
			})
		},
	}
}

func pirAcceptCmd() *cobra.Command {
	var lease, bearer string
	c := &cobra.Command{
		Use:   "accept",
		Short: "Open a lease for a derived bearer (winner only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if lease == "" || bearer == "" {
				return fmt.Errorf("need --lease and --bearer")
			}
			return pir.AcceptBid(lease, bearer)
		},
	}
	c.Flags().StringVar(&lease, "lease", "", "lease id")
	c.Flags().StringVar(&bearer, "bearer", "", "64-hex derived bearer")
	return c
}

func pirCloseCmd() *cobra.Command {
	var lease string
	c := &cobra.Command{
		Use:   "close",
		Short: "Close a lease (winner bearer denied)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if lease == "" {
				return fmt.Errorf("need --lease")
			}
			return pir.CloseLease(lease)
		},
	}
	c.Flags().StringVar(&lease, "lease", "", "lease id")
	return c
}

func pirAccessCmd() *cobra.Command {
	var lease, bearer string
	c := &cobra.Command{
		Use:   "access",
		Short: "Check derived-bearer access for a lease (ok|closed|unauthorized|unknown)",
		RunE: func(cmd *cobra.Command, args []string) error {
			st := pir.AccessLease(lease, bearer)
			fmt.Println(st)
			if st != "ok" {
				return fmt.Errorf("access %s", st)
			}
			return nil
		},
	}
	c.Flags().StringVar(&lease, "lease", "", "lease id")
	c.Flags().StringVar(&bearer, "bearer", "", "64-hex derived bearer")
	return c
}

func pirServeCmd() *cobra.Command {
	var lease, bearer, image string
	var port int
	c := &cobra.Command{
		Use:   "serve",
		Short: "Allocate (if commit gate allows) and docker-run a lightweight HTTP container",
		RunE: func(cmd *cobra.Command, args []string) error {
			if lease == "" || bearer == "" {
				return fmt.Errorf("need --lease and --bearer")
			}
			if !pirgate.PirAllocationAllowed() {
				return fmt.Errorf("allocate denied (commit / zap1 gate)")
			}
			id, p, err := pir.ServeLease(lease, bearer, image, port)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(os.Stdout)
			return enc.Encode(map[string]any{
				"container": id,
				"port":      p,
				"running":   pir.ContainerRunning(lease),
				"served":    true,
			})
		},
	}
	c.Flags().StringVar(&lease, "lease", "", "lease id")
	c.Flags().StringVar(&bearer, "bearer", "", "64-hex derived bearer")
	c.Flags().StringVar(&image, "image", "", "docker image (default python:3.12-alpine)")
	c.Flags().IntVar(&port, "port", 18765, "host port")
	return c
}

func pirStopCmd() *cobra.Command {
	var lease string
	c := &cobra.Command{
		Use:   "stop",
		Short: "Stop the lease container and close access",
		RunE: func(cmd *cobra.Command, args []string) error {
			if lease == "" {
				return fmt.Errorf("need --lease")
			}
			return pir.StopServe(lease)
		},
	}
	c.Flags().StringVar(&lease, "lease", "", "lease id")
	return c
}

func pirSidecarCmd() *cobra.Command {
	var addr string
	c := &cobra.Command{
		Use:   "sidecar",
		Short: "Keep-alive health for ict-rs; exec pir serve/stop against the mounted docker socket",
		RunE: func(cmd *cobra.Command, args []string) error {
			if p := os.Getenv("PIR_LEASE_BOOK_FILE"); p != "" {
				_ = os.MkdirAll(filepath.Dir(p), 0o700)
			}
			mux := http.NewServeMux()
			mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"ok":        true,
					"allocate":  pirgate.PirAllocationAllowed(),
					"envelope":  pirgate.EnvelopeLoaded(),
					"match_url": pirgate.CommitMatchURLSet(),
					"matches":   pirgate.LiveCommitMatches(),
				})
			})
			fmt.Fprintf(os.Stderr, "pir sidecar listening %s\n", addr)
			return http.ListenAndServe(addr, mux)
		},
	}
	c.Flags().StringVar(&addr, "addr", ":8444", "listen address")
	return c
}

func pirSealCmd() *cobra.Command {
	var askID, bidder, endpoint, sessionHex, nonceHex, envelopeOut string
	var price uint64
	c := &cobra.Command{
		Use:   "seal",
		Short: "Seal a ChaCha20-Poly1305 OOB bid envelope and print bid-commit-v1 hex",
		RunE: func(cmd *cobra.Command, args []string) error {
			if sessionHex == "" {
				sessionHex = os.Getenv("PIR_SESSION_KEY")
			}
			key, err := pirgate.ParseKey32(sessionHex)
			if err != nil {
				return err
			}
			nonce, err := pirgate.ParseNonce16(nonceHex)
			if err != nil {
				return err
			}
			env, err := pirgate.SealEnvelope(pirgate.PlaintextBid{
				AskID:            askID,
				BidderIdentity:   bidder,
				PriceUakt:        price,
				ProviderEndpoint: endpoint,
			}, key, nonce)
			if err != nil {
				return err
			}
			commit := env.Commitment()
			bearer := pir.BearerHex(pir.SecretFromSession(askID, key, commit))
			if envelopeOut != "" {
				raw, err := json.Marshal(env)
				if err != nil {
					return err
				}
				if dir := filepath.Dir(envelopeOut); dir != "" && dir != "." {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						return err
					}
				}
				if err := os.WriteFile(envelopeOut, raw, 0o600); err != nil {
					return err
				}
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			return enc.Encode(map[string]any{
				"ask_id":         askID,
				"bid_commitment": env.CommitmentHex(),
				"bearer":         bearer,
				"envelope":       env,
				"envelope_path":  envelopeOut,
			})
		},
	}
	c.Flags().StringVar(&askID, "ask-id", "ask-1", "public ask id")
	c.Flags().StringVar(&bidder, "bidder", "prov", "bidder identity (OOB only)")
	c.Flags().Uint64Var(&price, "price", 9000, "price_uakt (OOB only)")
	c.Flags().StringVar(&endpoint, "endpoint", "oob://p", "provider endpoint (OOB only)")
	c.Flags().StringVar(&sessionHex, "session-key", "", "32-byte hex session key (or PIR_SESSION_KEY)")
	c.Flags().StringVar(&nonceHex, "nonce", "", "optional 16-byte hex nonce")
	c.Flags().StringVar(&envelopeOut, "envelope-out", "", "write raw envelope JSON")
	return c
}

func pirMatchServeCmd() *cobra.Command {
	var addr string
	c := &cobra.Command{
		Use:   "match-serve",
		Short: "Local cw-pir-commit Match JSON: POST /match → {matches:true}",
		RunE: func(cmd *cobra.Command, args []string) error {
			ask, _ := pirgate.Hex64Env("PIR_ASK_COMMIT", "PIR_ASK_COMMIT_FILE")
			bid, _ := pirgate.Hex64Env("PIR_BID_COMMIT", "PIR_BID_COMMIT_FILE")
			store := pirgate.NewCommitStore(ask, bid)
			fmt.Fprintf(os.Stderr, "cw-pir-commit match listening %s\n", addr)
			return http.ListenAndServe(addr, pirgate.CommitMatchHandler(store))
		},
	}
	c.Flags().StringVar(&addr, "addr", ":8080", "listen address")
	return c
}
