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

> **Building your own SDK on top of Slipstream** (any language)? Start with
> **[`HOSTING.md`](HOSTING.md)** — the complete host contract: what to call to get
> `data.db` filled, how to read the snapshot/events/SQL surface correctly, and the short
> list of rules that keep a host thin and bug-free.

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
cargo test -p slipstream-core -p slipstream-cli   # the always-green gate (180 + 29 tests)
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

## Status & versioning

| Milestone | What it is |
|---|---|
| **v0.1** | Foundation: the first engine cut — 64 min → 16 min restore. |
| **v0.2** | The engine rewrite: record device runs (iPad A10 8:32, iPhone ~1:20), ~12× over the reference SDK sync; in production use in the Zodl wallet. |
| **v0.2.5** | Restore-correctness era (shipped in Zodl betas): read-side reconciliation view (`slipstream_v_tx_reconciled`), never-overshoot recovery balance, transient-network resilience. |
| **v0.3** | **Engine API v2 — exported wallet semantics**: the engine now owns what every host used to re-derive. Snapshot carries `is_recovering` (scheduler-computed, terminal fail-safe latch built in), blessed monotonic `progress_permille` (seeded with the wallet's global position, so a catch-up reads ~100% and an interrupted restore resumes where it left off), and `stalled_seconds`; the event ring is criticality-aware (done/error/found-transactions survive overflow); `slipstream_v_recovery_balance` joins the versioned SQL views; hosts can poke `notify_tx_change` after a broadcast; and a unified wallet-summary FFI resolves the recovery phase internally. One `derive_snapshot` is shared by the C FFI and Rust hosts — proven by the `slipstream watch` CLI acting as a second host with zero wallet math of its own. |
| **v0.3.5** | **Engine API v2.1 — the thin-host sweep**: the remaining wallet policy hosts still carried moved down, so a host is marshalling + delivery and nothing else. The snapshot is **truthful from open** (recovery flag, progress floor, persisted tip and spendability seeded from the wallet DB — no pre-first-scan blind window, a mid-restore relaunch reads correctly from the first poll); the unified wallet summary **rations its own cost** (serve-cached + background refresh at range boundaries — hosts may call it every tick, it never competes with scanning); `tip_fresh` reports whether the *current run* has proven the chain tip (stale-tip spendable masking becomes an engine fact); `tx_set_version` monotonically versions the stored transaction set — one host rule, "version moved → re-fetch", covering enhancement writes, mined/expired transitions, mempool hits, scan-driven reconcile linkage and post-broadcast pokes; the progress floor **re-baselines itself when the scan scope expands**, so importing an account with an older birthday reads as a genuine 0→100% climb; and the new handle-less **`restore_anchor`** primitive owns wallet provisioning — restore `recover_until` with an offline bundled-checkpoint fallback, reorg-safe new-wallet tree state, Tor-or-offline (never a de-anonymising direct retry). |
| **v0.3.6** | **Lifecycle hardening** (this repo's current snapshot — the finish-line wave before the first slipstream-default wallet release): the wallet file is **quiescent when a session stops** — the write-behind commit holds a writer gate for its whole life (compute + transaction) and stop/start DRAIN it and JOIN the aborted pass, so a host wallet write (account delete/import, rewind truncate) can never interleave with an orphaned engine write; **orphaned historic scan ranges are pruned at every session open** (upstream `delete_account` leaves the deleted account's deep ranges queued — without the prune, a wallet grinds a phantom restore for keys that no longer exist, and a wedged wallet now self-heals at its next open); and the session **revives after non-transient pass failures** with a capped backoff (15 s → 5 min) instead of staying dead until relaunch — every failure still surfaces truthfully, but one-shot causes self-heal on the first attempt (validated in the field the day it shipped). |
| **v0.4** | (planned) The performance lever, renumbered from the old v0.3 slot: GPU/SIMD work reduction — the parked GPU subtree kernel (narrow win that regressed device extremes; see the perf-learnings doc) and the SIMD trial-decryption exploration. |

This repository contains the **v0.3.6** snapshot (tag `v0.3.6`), re-extracted from the
development tree (the Zodl wallet SDK's `slipstream` branch) — it includes the v0.2.5
restore-correctness work, the full engine API v2, and the v2.1 thin-host sweep.

## License

MIT © 2026 Lukas Korba. Chosen deliberately so the engine can be adopted, or moved into
another org, without friction.
