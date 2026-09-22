# Slipstream

<img width="2400" height="1260" alt="slipstream-social-1200x630-dark-2400" src="https://github.com/user-attachments/assets/5e7cfa97-3991-43e3-a164-f5d7a5619aa5" />

A high-performance sync engine for Zcash light wallets. Slipstream re-architects the
download → trial-decrypt → commitment-tree → persist pipeline to sync **dramatically faster**
than the reference path — while producing a **byte-identical** wallet database.

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
reference engines. See `REVIEWING.md` for the module map.

## Design — "upstream brain, Slipstream body"

Every cryptographic and wallet-logic decision is delegated to the `librustzcash` crates
(`zcash_client_backend`, `zcash_client_sqlite`, `shardtree`, `sapling`) — unmodified,
published on crates.io. 

Slipstream owns only the **orchestration**: parallel block fetch with a device-RAM-scaled byte
budget, a sparse in-memory commitment tree with a checkpoint-downgrade, a write-behind
persistence lane, spend-before-sync scan ordering, tip-following, mempool, a per-call Tor
transport policy, and resilience.

Because the engine is a *consumer* of `librustzcash`, it is platform-neutral Rust:
it powers an iOS wallet SDK today (via an FFI layer that lives in the consuming SDK, not here)
and can be embedded anywhere Rust runs.

| Crate | Role |
|---|---|
| `core` — `zodl-slipstream` | the engine |
| `cli` — `slipstream-cli` | benchmark / golden-oracle / A-B harness |
| `gpuhash` — `zodl-slipstream-gpuhash` | **parked** GPU Sinsemilla kernel — off by default; a default build links zero `wgpu` |
| `protogen` — `slipstream-protogen` | dev-only gRPC code generator |

## Correctness

The headline safety property: Slipstream produces a **byte-identical `data.db`** versus the
upstream reference sync. This is enforced on every change by a **golden oracle**
(`semantic_diff`) plus **hermetic darkside oracles**. Speed changes; wallet-state semantics do
not.

## Build & test

```sh
cargo test -p zodl-slipstream -p slipstream-cli   # the always-green gate (228 + 32 tests)
cargo build --workspace                           # full workspace incl. the parked gpuhash
```

Edition 2024, Rust 1.90+. Dependencies are published crates.io releases.

## Documentation

- **`HOSTING.md`** — the crate consumer's guide: what to call, in what order, and how to
  read the results correctly.
- **`REVIEWING.md`** — module map for protocol engineers.

## License

Copyright © 2026 Znewco, Inc. (d/b/a Zcash Open Development Lab)

ZODL Slipstream is free software, licensed under the GNU Affero General
Public License, version 3 only (AGPL-3.0-only). See [LICENSE](LICENSE).

In short: you may use, study, modify, and redistribute ZODL Slipstream, but
if you incorporate it into an application, the complete source of that
application must be made available under the AGPL to its users,
including users who interact with it over a network.

If those terms don't fit your project, **commercial licenses are
available** — see [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).
Official Zodl builds distributed through the Apple App Store are
released by Znewco under separate terms; no App Store distribution
permission is granted to AGPL licensees — see
[LICENSE-EXCEPTIONS.md](LICENSE-EXCEPTIONS.md).

ZODL Slipstream depends on the Zcash Rust crates (librustzcash and
related), which are separately licensed under MIT/Apache-2.0 by their
respective copyright holders and are not covered by this notice.
