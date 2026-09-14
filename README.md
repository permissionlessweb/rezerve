# re-zerve

Privacy-first compute rent with an Akash-shaped market: public **deployment/ask**, encrypted **bid** off-chain, **commitment-only** on-chain record, FROST threshold spends, Ironwood notes.

GitHub: https://github.com/permissionlessweb/rezerve

**Documentation is the AEP:** [`aep/spec/aep-xxx/README.md`](aep/spec/aep-xxx/README.md). Field tables: [`aep/spec/aep-xxx/data-structures.md`](aep/spec/aep-xxx/data-structures.md). Crate and Halo2 map: [`aep/spec/aep-xxx/crate-map.md`](aep/spec/aep-xxx/crate-map.md).

## Layout

| Path | What |
|---|---|
| `aep/` | Sole documentation. |
| `crate/` | Rust crate `private-inference-rent` (circuit, CosmWasm, tests). |
| `provider/` | `provider-services` fork (`pirgate`, `gateway/pir`, `cmd/pir-sidecar`). |
| `crate/scripts/` | Lab e2e. |
| `scripts/` | Sync into cargo/go working trees. |

## Build

Compile and e2e on a dedicated lab machine. Set `REZERVE_LAB_HOST` if you ssh:

```bash
export REZERVE_LAB_HOST=your-lab-host
ssh "$REZERVE_LAB_HOST"
cd ~/abstract/re-zerve
sh scripts/sync-working-trees.sh
```

Working trees (path deps, not git): `~/abstract/terp-core/crates/private-inference-rent`, `~/abstract/terp-core/crates/akash-provider-pir`.

## License

MIT OR Apache-2.0 for the crate. Provider fork inherits Akash provider Apache-2.0. AEP text is Apache-2.0 per AEP-1.
