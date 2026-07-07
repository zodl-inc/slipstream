# Slipstream

<img width="2400" height="1260" alt="slipstream-social-1200x630-dark-2400" src="https://github.com/user-attachments/assets/5e7cfa97-3991-43e3-a164-f5d7a5619aa5" />

A high-performance sync engine for Zcash light wallets. Slipstream re-architects the
download → trial-decrypt → commitment-tree → persist pipeline to sync **dramatically faster**
than the reference path — while producing a **byte-identical** wallet database.

> **Independent project.** Slipstream is a personal R&D project by Lukas Korba. It is **not**
> an Electric Coin Company, Zcash Foundation, or company product, and carries no endorsement
> from them. It builds on the official `librustzcash` crates published on crates.io; since
> v0.5 two of them (`orchard`, `zcash_note_encryption`) are carried as minimally-patched
> vendored forks — byte-identical output, headed upstream.

> **Reviewing or auditing?** Start with **[`REVIEWING.md`](REVIEWING.md)** — a dense
> module-and-data-flow map (where to look, and why) written for Zcash protocol engineers.

> **Building your own SDK on top of Slipstream** (any language)? Start with
> **[`HOSTING.md`](HOSTING.md)** — the complete host contract: what to call to get
> `data.db` filled, how to read the snapshot/events/SQL surface correctly, and the short
> list of rules that keep a host thin and bug-free.

## Result

One real wallet, four devices, defaults only (v0.5). Reference times: the stock
ZcashLightClientKit on the same wallet.

| Device | Reference SDK | Slipstream |
|---|---|---|
| MacBook Pro (M4) | 22:30 | **~20 s** (~70×) |
| iPhone (A18) | 16:55 | **43 s** (~24×) |
| iPad Air (A14) | 25:11 | **68 s** (~23×) |
| iPad 2016 (A10, 2 GB RAM) | 1:04:26 | **4:43** (~14×) |

Deep history holds up: a real 2019 wallet — ~2.4M blocks including the entire 2022–23
"sandblasting" spam era — restores in **51 minutes** (M4), a range effectively
unrestorable on the reference path. On device, Slipstream also beats the Zingo and Zkool
reference engines. Methodology and full numbers in `docs/`.

## Design — "upstream brain, Slipstream body"

Every cryptographic and wallet-logic decision is delegated to the `librustzcash` crates
(`zcash_client_backend`, `zcash_client_sqlite`, `shardtree`, `sapling`) — unmodified,
published on crates.io. Two crates (`orchard`, `zcash_note_encryption`) are vendored under
`vendor/` as minimally-patched forks carrying the v0.5 trial-decrypt seam (batched-DH hook +
GLV endomorphism ladder) — byte-identical output, KAT-gated, tracked for upstreaming.

Slipstream owns only the **orchestration**: parallel block fetch with a device-RAM-scaled byte
budget, a sparse in-memory commitment tree with a checkpoint-downgrade, a write-behind
persistence lane, spend-before-sync scan ordering, tip-following, mempool, a per-call Tor
transport policy, and resilience.

Because the engine is a *consumer* of `librustzcash`, it is platform-neutral Rust:
it powers an iOS wallet SDK today (via an FFI layer that lives in the consuming SDK, not here)
and can be embedded anywhere Rust runs.

| Crate | Role |
|---|---|
| `core` — `slipstream-core` | the engine |
| `cli` — `slipstream-cli` | benchmark / golden-oracle / A-B harness |
| `gpuhash` — `slipstream-gpuhash` | **parked** GPU Sinsemilla kernel — off by default; a default build links zero `wgpu` |
| `protogen` | dev-only gRPC code generator |
| `vendor/` | the two patched forks (`orchard`, `zcash_note_encryption`), wired via `[patch.crates-io]` |

## Correctness

The headline safety property: Slipstream produces a **byte-identical `data.db`** versus the
upstream reference sync. This is enforced on every change by a **golden oracle**
(`semantic_diff`) plus **hermetic darkside oracles**. Speed changes; wallet-state semantics do
not.

## Build & test

```sh
cargo test -p slipstream-core -p slipstream-cli   # the always-green gate (228 + 32 tests)
cargo build --workspace                           # full workspace incl. the parked gpuhash
```

Edition 2024, Rust 1.90+. Dependencies are published crates.io releases plus the two
vendored forks under `vendor/`.

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
| **v0.1** | Foundation. First engine cut: 64 min → 16 min restore. |
| **v0.2** | Engine rewrite. ~12× the reference SDK (iPad A10 8:32, iPhone ~1:20). |
| **v0.2.5** | Restore correctness. Read-side reconciliation view, never-overshoot recovery balance, transient-network retry. |
| **v0.3** | Engine API v2. Engine-owned wallet semantics: `is_recovering`, monotonic `progress_permille`, `stalled_seconds`, criticality-aware event ring, recovery-balance view, unified wallet-summary FFI. |
| **v0.3.5** | API v2.1 — thin hosts. Snapshot truthful from open. Self-rationing wallet summary. `tip_fresh`, `tx_set_version`. Progress re-baselines when scan scope expands. `restore_anchor` owns wallet provisioning. |
| **v0.3.6** | Lifecycle hardening. Wallet file quiescent on stop (writer gate: drain + join). Orphaned scan ranges pruned at open. Session revival with capped backoff. |
| **v0.4** | "Graft, don't grind" — work reduction, **on by default**. Restores 13–46% faster fleet-wide. Subtree-root grafting (1-in-16 sampling audit; gates included a Halo2-adjudicated spend-from-grafted-witness proof and a 19/19 mainnet root audit) + batch-affine Sinsemilla (~12× the scalar combine). Byte-identical. Kill switches: `ZCASH_GRAFT_SUBTREE=0`, `ZCASH_BATCH_COMBINE=0`. |
| **v0.5** | Scan pacer — **on by default**. Another 26–42% off restores. Boundary treestate prefetch (server RTT fully hidden; sync times stop swinging with server weather). Gated interleaved enhancement. GLV endomorphism trial-decrypt DH (−24% DH core-time, byte-identical, KAT-gated). Negatives recorded honestly: lockstep batched-DH kernel and local treestate derivation were built, measured, and rejected. Kill switch: `ZCASH_ENDO_MUL=0`. |
| **v0.5.1** | Sandblasting-era restore fix. Deep-history batches no longer flood the checkpoint store (v0.4 graft interaction — panicked mid-era); damaged wallets self-heal at the next session open. Red-proven regression tests; validated by a full-era 2.4M-block restore. |

This repository is the **v0.5.1** snapshot (tag `v0.5.1`), re-extracted from the
development tree (the Zodl wallet SDK's `slipstream` branch).

## License

MIT © 2026 Lukas Korba. Chosen deliberately so the engine can be adopted, or moved into
another org, without friction.

The `vendor/` directory carries minimally-patched forks of the upstream `orchard` and
`zcash_note_encryption` crates (the v0.5 DH seam + endomorphism ladder); they retain
their upstream MIT/Apache-2.0 dual licenses — see the LICENSE files inside each fork.
