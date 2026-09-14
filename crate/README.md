# private-inference-rent

Offline protocol for a privacy-preserving compute-rent *shape*: public ask, ChaCha20-Poly1305 OOB bids, commitment-only chain view, local sim transcripts vs product ZAP1 ingest, two-layer t-of-n committees.

Pay inclusion is **ZAP1 Merkle + IBC v2 packet attest** (`credit_deposit_zap1`). Crosslink 08-wasm verifies **headers only** and is not that path. Halo2: `crate/circuits/hosting-payment`, host `proof_instance_verify`. Documentation: [`../aep/spec/aep-xxx/README.md`](../aep/spec/aep-xxx/README.md).

```bash
ssh "$REZERVE_LAB_HOST" 'export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
  cd ~/abstract/terp-core/crates/private-inference-rent && cargo test'
```
