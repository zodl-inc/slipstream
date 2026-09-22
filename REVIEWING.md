# Slipstream — Reviewer's Guide

> For Zcash protocol / cryptographic engineers. This is a **map** — where to look and why — not a
> tutorial.
> The engine consumes **canonical** librustzcash — crates.io releases where published; the
> Ironwood-era family rides `[patch.crates-io]` onto `zcash/librustzcash` main at a pinned rev
> (see `Cargo.toml`), never a third-party fork. It adds *scheduling,
> persistence shape, and transport policy* — **not cryptography**.

## TL;DR
A mobile-first compact-block sync engine. Same wallet DB and note-commitment math as
`zcash_client_backend` / `zcash_client_sqlite` — the novelty is **how** it drives them: non-linear
Spend-before-Sync scheduling, concurrent density-adaptive fetch, an in-memory **sparse**
commitment-tree persistence path, depth-N in-order write-behind, a per-call Tor policy, and a
host-agnostic autonomous session. Every acceleration is **byte-identical** to upstream's `put_blocks`
and is oracle-gated. Note decryption, nullifier derivation, and tree hashing are **not** reimplemented.

## Start here (in order)
| # | Read | Why |
|---|------|-----|
| 1 | `core/src/engine.rs` → `sync_once` | One full pass, top to bottom — the spine. |
| 2 | `core/src/session.rs` → `run_session` | The autonomous lifecycle around passes (Tor bootstrap → resilient initial pass → follow + mempool). The single host entry point. |
| 3 | `core/src/scheduler.rs` → `run_to_completion` | Drives suggested scan-ranges → fetch/scan/persist/enhance per range. |
| 4 | `core/src/persist.rs` | The interesting persistence: sparse ShardTree + write-behind. The perf win **and** the byte-identity. |
| 5 | `cli/src/main.rs` → `cmd_sync`, `cmd_oracle` | Runnable harness + the correctness oracle. |

## Module map (`core/src/`)
| File | Responsibility |
|------|----------------|
| `engine.rs` | `sync_once` (one pass), `probe_tip`, `should_resync`, `SyncOutcome`, `ENGINE_BUILD`. |
| `session.rs` | `run_session` autonomous lifecycle; `SessionConfig` / `SessionReporter`; retry/jitter/backoff. |
| `scheduler.rs` | `run_to_completion`: Spend-before-Sync scan-range loop + per-range enhancement. |
| `scan.rs` | `scan_chunks`: batched `scan_cached_blocks`; treestate prefetch + bounded retry. |
| `census.rs` | v0.4: per-wallet shard census (touched/noted/graftable fraction — predicts the graft ceiling) + the BenchSummary JSON writer. |
| `graft.rs` | v0.4: the restart-safe graft buffer table (side connection; pre-txn appends, post-commit cleanup) + `server_root` lookup. |
| `graft_accumulator.rs` | v0.4: pure per-pool state machine — buffer note-free shards, eager-flush on the first owned note, close-clean at shard boundaries; range-end shards always build. |
| `batch_sinsemilla.rs` | v0.4: batch-affine Sinsemilla combine (lockstep half-steps, one Montgomery batch inversion each) — byte-identical, KAT-gated. |
| `lookup_build.rs` | v0.4: the shared lookup-build machinery (precompute map → verbatim `from_iter` → convert) parameterized by a batch-combine fn; routes batch > gpu > scalar. |
| `treestate.rs` | v0.5 (parked, default OFF): local running-frontier treestate derivation + off-path server audit + process fuse — built, audited byte-identical, measured out (naive per-leaf absorb costs more than the RTT it saves); revival path = batch-affine bulk absorb. |
| `fetch.rs` | Concurrent `GetBlockRange` (N streams); byte-budgeted sub-chunk splitting (sandblasting era); resume-on-cut; v0.7 P2: clock-free wire-collapse detector (STALL/COLLAPSE triggers) + bounded (≤ 2) mid-pass failover. |
| `persist.rs` | Sparse in-memory `ShardTree` `put_blocks`; checkpoint-downgrade; `WriteBehindFacade` + persist lane (depth-N, **in-order, serial**). |
| `connector.rs` | Per-call Tor policy (`ConnPurpose` → circuit); `TorConn` bootstrap; bounded circuit-build + retry-on-fresh-circuit. |
| `grpc.rs` | lightwalletd tonic client; unary/stream helpers + deadlines; `retry_get_tree_state`. |
| `enhance.rs` | `run_enhancement`: `GetTransaction` / `TransactionsInvolvingAddress`, dedup. |
| `transparent.rs` | `refresh_utxos` — runs **before** the shielded scan (mirrors upstream `sync.rs`). |
| `mempool.rs` | `run_session`: `GetMempoolStream` → `decrypt_and_store_transaction` (0-conf); non-fatal. |
| `wallet_session.rs` | `WalletSession` — the `zcash_client_sqlite` `WalletDb` wrapper + account import; persisted-state reads (`chain_height`, `max_recover_until`, `min_birthday`, `tx_set_signature`). |
| `reconcile.rs` | `slipstream_v_tx_reconciled` — read-side view flagging txs whose shielded spend hasn't linked yet (recent-first restore visibility; installed idempotently at `WalletSession::open`). |
| `scan_queue.rs` | `prune_orphaned_historic_ranges` — drops Historic queue rows below every remaining account's birthday at `WalletSession::open` (an account deleted mid-restore leaves its deep ranges queued; upstream `delete_account` never touches `scan_queue`). |
| `anchor.rs` | `restore_anchor` — wallet-provisioning primitive (restore `recover_until` with offline checkpoint fallback; reorg-safe new-wallet tree state; Tor-or-offline, never a direct de-anonymising fallback). |
| `chunk.rs`, `block_source.rs` | In-memory chunk buffering / block-source plumbing feeding the scan kernel; v0.5: `ChunkQueueSender` boundary-fetcher hook — the per-chunk treestate fetch spawns at chunk EMIT so the RTT hides under queue+scan+submit. |
| `events.rs` | `Progress` (poll atomics), `Event`, `Snapshot` — the host-facing progress surface. |
| `ffi_handle.rs` | `SlipstreamHandle` (runtime + state + event ring), `SyncState`, `FfiSlipstreamSnapshot/Event`, `spawn_supervised` (panic → `Error`). |
| `oracle.rs` | `semantic_diff` — row/byte-level `data.db` equivalence vs the upstream path. |
| `verify.rs` | Server / scan-continuity validation. |
| `config.rs` | `EngineConfig` (tunables, device-memory derate, `alternate_endpoints`, `anchor_retention_height`), `Endpoint`. |
| `probe.rs` | v0.7 P1: endpoint probing/racing across `EngineConfig.alternate_endpoints` — picks a healthy server before a pass and feeds the mid-pass failover loop. |
| `throttle.rs` | v0.7 P0: local TCP throttle proxy (token bucket) — the test-only "weather machine" for simulating sick servers; never on a production path. |
| `network.rs` | `SlipstreamNetwork` — custom consensus params / activation heights (CLI `--custom-heights`, `--network test`) for exercising Ironwood/NU6.3 against modified-parameter chains pre-activation. |
| `error.rs` | `SlipstreamError` + `is_transient` (drives every retry decision). |

`gpuhash/` (crate `zodl-slipstream-gpuhash`, cargo feature `gpu`, **default-off**) — wgpu Orchard Sinsemilla
combine; byte-identical to `MerkleHashOrchard::combine` (KAT-gated). Released builds link zero wgpu.

## Sync data flow (one pass)
**Preflight** (`sync_once`): import account if the DB has none (UFVK + birthday treestate) →
`get_subtree_roots` / `put_subtree_roots` → chain tip → **transparent UTXO refresh** (before shielded)
→ `run_to_completion`:
- `suggest_scan_ranges` → **ChainTip priority, then Historic** (Spend-before-Sync; non-linear order, so
  spendable notes surface first).
- per range: **fetch** (≤ N concurrent streams; each plan-chunk split into ≤ `chunk_split_bytes`
  sub-chunks so the dense ~1.70–2.00M "sandblasting" era can't blow memory or the deadline; retries
  resume from the last emitted height) → **scan** (`scan_cached_blocks`, optionally time-sliced
  sub-batches) → **persist** (sparse: decrypt feeds an in-memory `ShardTree`, flushed once per chunk;
  **write-behind** runs chunk N's commit overlapped with N+1's decrypt, strictly in-order) →
  **interleaved enhancement** every few chunks.
- final `run_enhancement`, then the `sync stage split` log line (the perf ground truth:
  total / fetch / scan / enhance + persist_wait / persist_overlap + `bound`).

Then `run_session` **follows**: jittered tip poll (10–30 s, anti-fingerprint) gated by a held
`GetMempoolStream` (0-conf detection), keyless catch-up passes — all transient-tolerant.

## What to scrutinize (the claims, with file refs)
- **Sparse persistence** (`persist.rs`; book `07-sparse-persistence`): the magnitude win — an in-memory
  `ShardTree` + **checkpoint-downgrade** replaces upstream's per-block SQLite tree I/O. Claim:
  byte-identical `data.db`. Kill switch `EngineConfig.sparse_persistence=false`.
- **Write-behind** (`persist.rs` lane / `WriteBehindFacade`): persist overlaps scan but stays
  **in-order + serial** ⇒ identical bytes at any `persist_depth` (default 1 = legacy strict backpressure).
- **Tor policy** (`connector.rs`; book `15-privacy`): mirrors the old SDK `ServiceMode` —
  **bulk `GetBlockRange` is direct even with Tor on** (volume; per-user exposure is identical with or
  without Tor — documented threat model), wallet-identifying metadata over **isolated** circuits.
  Bounded circuit-build + retry-on-fresh-circuit (anti-stall). Bootstrap **never** silently falls to direct.
- **Autonomous session** (`session.rs`, `ffi_handle.rs::spawn_supervised`): the initial pass never
  surfaces a hard error on a transient/transport fault (retries with backoff, shows Disconnected); the
  follow loop never Errors; a panic becomes `SyncState::Error(2)` via the supervisor, not a silent hang.
- **GPU combine** (`gpuhash/`): optional offload, default-off, KAT + oracle byte-identical.

## Correctness contract
Acceleration paths are **proven byte-identical** to upstream's audited `put_blocks`:
- `oracle.rs::semantic_diff` + the `cli oracle` subcommand (run A = upstream path, run B =
  sparse / write-behind / gpu) ⇒ `VERDICT IDENTICAL` on mainnet + synthetic data.
- Hermetic + darkside integration tests in `core/tests/` (reorg, spendability, truncate; book
  `13-correctness-oracle`).
- The engine decides **order, batching, persistence shape, and transport** — never the crypto.

## Host / FFI boundary
Host-agnostic. One entry: `session::run_session(SessionConfig, SessionReporter)`. Hosts consume a
**poll model** — `ffi_handle::SlipstreamHandle::snapshot()` + a drained event ring — with **no FFI
callbacks** across the language boundary. The C ABI and the Swift layer live in the **SDK** repo
(`ZcashLightClientKit`), a thin veneer over this crate; a new host (e.g. an Android JNI shim) is the
same thin veneer. No key custody lives here beyond UFVK import (keys are `zcash_keys`).

## Build / run / verify
```sh
cargo test -p zodl-slipstream -p slipstream-cli                 # the always-green gate
cargo run  -p slipstream-cli -- sync   --server <lwd> --wallet-dir <dir> --ufvk <ufvk> --birthday <h>
cargo run  -p slipstream-cli -- oracle --server <lwd> --wallet-a <a> --wallet-b <b> \
           --ufvk <ufvk> --birthday <h> --sparse-b --write-behind-b   # byte-identity → VERDICT IDENTICAL
```
