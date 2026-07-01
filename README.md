# Slipstream

<img width="2400" height="1260" alt="slipstream-social-1200x630-dark-2400" src="https://github.com/user-attachments/assets/5e7cfa97-3991-43e3-a164-f5d7a5619aa5" />

A high-performance sync engine for Zcash light wallets. Slipstream re-architects the
download → trial-decrypt → commitment-tree → persist pipeline to sync **dramatically faster**
than the reference path — while producing a **byte-identical** wallet database.

> **Independent project.** Slipstream is a personal R&D project by Lukas Korba. It is **not**
> an Electric Coin Company, Zcash Foundation, or company product, and carries no endorsement
> from them. It builds *on top of* the official `librustzcash` crates published on crates.io —
> it does not fork or modify them.

> **Reviewing or auditing?** Start with **[`REVIEWING.md`](REVIEWING.md)** — a dense
> module-and-data-flow map (where to look, and why) written for Zcash protocol engineers.

## Result

On a 2016 iPad (A10 Fusion) restoring a real multi-month wallet, the reference
ZcashLightClientKit took **1:04:26**; Slipstream brings the same restore to **~9 minutes
(≈7×)**. On an A14 iPad the engine rewrite measured **25:11 → 2:05 (~12×)**, and on device it
beats the Zingo and Zkool reference engines. Methodology and full numbers in `docs/`.

## Design — "upstream brain, Slipstream body"

Every cryptographic and wallet-logic decision is delegated to **unmodified** `librustzcash`
crates (`zcash_client_backend`, `zcash_client_sqlite`, `shardtree`, `orchard`, `sapling`).
Slipstream owns only the **orchestration**: parallel block fetch with a device-RAM-scaled byte
budget, a sparse in-memory commitment tree with a checkpoint-downgrade, a write-behind
persistence lane, spend-before-sync scan ordering, tip-following, mempool, a per-call Tor
transport policy, and resilience.

Because the engine is a *consumer* of published `librustzcash`, it is platform-neutral Rust:
it powers an iOS wallet SDK today (via an FFI layer that lives in the consuming SDK, not here)
and can be embedded anywhere Rust runs.

| Crate | Role |
|---|---|
| `core` — `slipstream-core` | the engine |
| `cli` — `slipstream-cli` | benchmark / golden-oracle / A-B harness |
| `gpuhash` — `slipstream-gpuhash` | **parked** GPU Sinsemilla kernel — off by default; a default build links zero `wgpu` |
| `protogen` | dev-only gRPC code generator |

## Correctness

The headline safety property: Slipstream produces a **byte-identical `data.db`** versus the
upstream reference sync. This is enforced on every change by a **golden oracle**
(`semantic_diff`) plus **hermetic darkside oracles**. Speed changes; wallet-state semantics do
not.

## Build & test

```sh
cargo test -p slipstream-core -p slipstream-cli   # the always-green gate (161 + 29 tests)
cargo build --workspace                           # full workspace incl. the parked gpuhash
```

Edition 2024, Rust 1.90+. Depends only on published crates.io `librustzcash`.

## Documentation

- **`docs/book/`** — *The Slipstream Book*: 20 chapters covering architecture, data model,
  fetch/scan/persist, reorgs, resilience, the correctness oracle, security, privacy,
  exploitability, performance, and tests. Start at `docs/book/index.html`.
- **`docs/plans/`** — phase-by-phase design records.
- **`docs/2026-06-15-perf-spikes-learnings.md`** — what was tried, measured, and parked
  (GPU offload, deeper write-behind pipelining) and why.

## Status

**v0.2** — the engine rewrite, in use in the Zodl iOS wallet; being prepared for external
review and audit. **v0.3** (a SIMD trial-decryption kernel) is planned. The GPU subtree kernel
is implemented but **parked** — a narrow win that regressed device extremes; see the
perf-learnings doc.

## License

MIT © 2026 Lukas Korba. Chosen deliberately so the engine can be adopted, or moved into
another org, without friction.
