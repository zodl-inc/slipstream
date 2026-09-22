// Copyright © 2026 Znewco, Inc. (d/b/a Zcash Open Development Lab)
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of ZODL Slipstream.
//
// ZODL Slipstream is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License,
// version 3 only, as published by the Free Software Foundation.
//
// ZODL Slipstream is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Affero General Public License for more details.
//
// Commercial licensing: see COMMERCIAL-LICENSE.md.

//! Slipstream developer CLI: the primary harness for engine work (decision D5).
//! Subcommands land per phase: `fetch` (P1), `sync` (P2+), `report` (P5).

use clap::{Parser, Subcommand};
use zcash_protocol::consensus::Parameters;
use zodl_slipstream::{BlockHeight, UnifiedFullViewingKey};

#[derive(Parser, Debug)]
#[command(
    name = "slipstream",
    version,
    about = "Slipstream sync engine dev harness"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print engine crate version info.
    Version,
    /// [v0.7 P0] The weather machine: run a local TCP proxy with a
    /// bandwidth cap in front of a lightwalletd, so "sick server" is
    /// reproducible on demand (plain TCP — point it at a --no-tls darkside
    /// or local lightwalletd; TLS upstreams pin their own hostname and are
    /// out of scope). Runs until Ctrl-C.
    ThrottleProxy {
        /// Upstream lightwalletd host:port (plain TCP), e.g. 127.0.0.1:9067
        #[arg(long)]
        target: String,
        /// Local port to listen on (0 = ephemeral, printed at start).
        #[arg(long, default_value_t = 0)]
        listen: u16,
        /// Bandwidth cap in KB/s for the server→client direction, shared
        /// across all connections (models server egress). 0 = uncapped.
        #[arg(long, default_value_t = 2_000)]
        cap_kbps: u64,
        /// [v0.7 P2] Scripted collapse: after this many seconds, retune the
        /// cap to --collapse-to-kbps (0 = no scripted collapse). The manual
        /// twin of the P4 mid-pass gate.
        #[arg(long, default_value_t = 0)]
        collapse_after_s: u64,
        /// Cap to collapse TO (KB/s) when --collapse-after-s fires.
        #[arg(long, default_value_t = 300)]
        collapse_to_kbps: u64,
    },
    /// Fetch a block range into memory and report throughput (G1 benchmark).
    Fetch {
        /// lightwalletd URL, e.g. <https://zec.rocks:443> or <http://127.0.0.1:9067>
        #[arg(long)]
        server: String,
        /// Inclusive range, e.g. 2500000..2600000 (start..end)
        #[arg(long)]
        range: String,
        /// Parallel streams for the measured run.
        #[arg(long, default_value_t = 4, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
        streams: usize,
        /// Blocks per chunk.
        #[arg(long, default_value_t = 10_000)]
        chunk: u32,
        /// Also run a K=1 baseline first (required for the G1 ratio).
        #[arg(long, default_value_t = true)]
        baseline: bool,
    },
    /// Derive a UFVK from a BIP-39 mnemonic (testnet fixture tooling — the
    /// phrase lands in shell history, so use it for TESTNET seeds only, e.g.
    /// wallets claimed from the Ironwood testnet faucet).
    DeriveUfvk {
        /// The BIP-39 mnemonic phrase (quote the whole phrase).
        #[arg(long)]
        mnemonic: String,
        /// ZIP-32 account index.
        #[arg(long, default_value_t = 0)]
        account: u32,
        /// Network the key encoding targets.
        #[arg(long, value_enum, default_value_t = NetworkArg::Test)]
        network: NetworkArg,
    },
    /// \[B7\] Send funds from a synced wallet (testnet spike tooling — the
    /// mnemonic lands in shell history, so use it for TESTNET seeds only).
    /// Defaults to a SELF-send (the account's own unified address).
    Send {
        /// Network the wallet database belongs to.
        #[arg(long, value_enum, default_value_t = NetworkArg::Test)]
        network: NetworkArg,
        /// lightwalletd URL to broadcast through.
        #[arg(long)]
        server: String,
        /// Wallet directory (a synced data.db must exist inside).
        #[arg(long)]
        wallet_dir: std::path::PathBuf,
        /// The BIP-39 mnemonic phrase for the spending key (quote it).
        #[arg(long)]
        mnemonic: String,
        /// ZIP-32 account index the wallet was derived from.
        #[arg(long, default_value_t = 0)]
        account: u32,
        /// Recipient address; omitted = the account's own unified address.
        #[arg(long)]
        to: Option<String>,
        /// Amount in zatoshis.
        #[arg(long, default_value_t = 10_000_000)]
        zats: u64,
    },
    /// Full sync pass into a wallet database (creates it if absent).
    Sync {
        /// Network the wallet database belongs to.
        #[arg(long, value_enum, default_value_t = NetworkArg::Main)]
        network: NetworkArg,
        /// [IW-0.5] Custom-chain activation heights: comma-separated
        /// `upgrade=height` pairs (keys: overwinter, sapling, blossom, heartwood,
        /// canopy, nu5, nu6, nu6_1, nu6_2), with the literal `genesis` as
        /// shorthand for "every known upgrade active from height 1" (later pairs
        /// override). When set, --network selects only the CONSTANTS (HRPs, coin
        /// type). The valargroup Ironwood testnet =
        /// `--network main --custom-heights genesis,nu6_2=5000`.
        #[arg(long)]
        custom_heights: Option<String>,
        /// lightwalletd URL, e.g. <https://zec.rocks:443> or <http://127.0.0.1:9067>
        #[arg(long)]
        server: String,
        /// Wallet directory (data.db lives inside).
        #[arg(long)]
        wallet_dir: std::path::PathBuf,
        /// UFVK to import on first run (required for a fresh wallet).
        #[arg(long)]
        ufvk: Option<String>,
        /// Birthday height for --ufvk import.
        #[arg(long)]
        birthday: Option<u64>,
        /// Parallel fetch streams.
        #[arg(long, default_value_t = 4, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
        streams: usize,
        /// Blocks per chunk.
        #[arg(long, default_value_t = 10_000)]
        chunk: u32,
        /// Use sparse in-memory commitment-tree persistence (P6, default on).
        /// Pass `--sparse false` to disable (kill switch — reverts to upstream path).
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        sparse: bool,
        /// \[B6\] Anchor-retention floor: checkpoints at heights >= this on the
        /// anchor-bucket grid become durable anchors (exempt from checkpoint
        /// downgrade/pruning) — the migration crate's pre-signed-transfer
        /// anchors. Off when omitted.
        #[arg(long)]
        anchor_retention: Option<u32>,
        /// \[B6\] Anchor-bucket grid, in blocks (default 144, the ZIP 318 value).
        /// MUST match the interval the wallet itself retains on, or a migration
        /// transfer anchored to a boundary this engine did not retain becomes
        /// unprovable. Only meaningful with `--anchor-retention`.
        #[arg(long, default_value_t = 144)]
        anchor_retention_interval: u32,
        /// Byte budget per fetch sub-chunk (T6.8-S adaptive split; makes dense
        /// "sandblasting" eras traversable). Must be >= 1 MiB.
        #[arg(long, default_value_t = zodl_slipstream::EngineConfig::DEFAULT_CHUNK_SPLIT_BYTES)]
        chunk_split_bytes: usize,
        /// T8.4: in-memory fetch/decode budget (bytes); must be >= 16 MiB. Lower it for
        /// memory-constrained runs — the device path derates this automatically from
        /// ProcessInfo.physicalMemory; this flag is the Mac/CLI equivalent (book ch.19).
        #[arg(long, default_value_t = zodl_slipstream::EngineConfig::DEFAULT_MEMORY_BUDGET)]
        memory_budget_bytes: usize,
        /// T6.9: depth-1 write-behind persistence pipelining (overlap chunk N's
        /// DB commit with chunk N+1's decryption). Requires sparse. Default ON
        /// since the 2026-06-12 flip; `--write-behind false` is the kill switch.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
        write_behind: bool,
        /// B0 (Phase B): compute Orchard subtree combines on the GPU (requires sparse and a
        /// build with `--features gpu`). Default off; CPU path identical when off.
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
        gpu_subtree: bool,
        /// Persist-pipelining: write-behind queue depth (max unpersisted units before scan
        /// blocks). 1 = legacy depth-1; higher hides more persist behind scan (~22% on modern
        /// devices) at the cost of RAM. The committed data.db is identical at any depth.
        #[arg(long, default_value_t = 1, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=64))]
        persist_depth: usize,
        /// T8.1: after reaching tip, keep the wallet tracking the chain.
        /// Probes the tip every 10–30 s (jittered); runs a full pass whenever a
        /// new block arrives. Cancellable with Ctrl-C. Useful for Mac CLI validation
        /// and for observing follow behaviour without a full Zodl build.
        #[arg(long, default_value_t = false)]
        follow: bool,
    },
    /// v0.4 P0 bench (spec §3.3): scripted fresh-restore benchmark. Restores the
    /// given UFVK into an EMPTY wallet dir (temp by default — a bench is always a
    /// fresh restore) and prints the engine's end-of-pass BenchSummary: stage
    /// split + shard census + the Plan-A graftable prediction, also written as
    /// JSON (the artifact bench-ios shares).
    Bench {
        /// Network the wallet database belongs to.
        #[arg(long, value_enum, default_value_t = NetworkArg::Main)]
        network: NetworkArg,
        /// lightwalletd URL, e.g. <https://zec.rocks:443>
        #[arg(long)]
        server: String,
        /// [v0.7 P1] Alternate lightwalletd URLs (repeatable). With any
        /// present, the pass probes all servers (~1 s) and commits the
        /// winner — the pit-crew lever's A/B switch.
        #[arg(long = "alternate-server")]
        alternate_server: Vec<String>,
        /// UFVK of the reference wallet to restore.
        #[arg(long)]
        ufvk: String,
        /// Birthday height for the restore.
        #[arg(long)]
        birthday: u64,
        /// Wallet directory (must NOT already contain a data.db). Default: temp dir.
        #[arg(long)]
        wallet_dir: Option<std::path::PathBuf>,
        /// v0.4 Plan A graft lever: skip building note-free completed shards by
        /// installing server roots (the A/B switch for the bet legs).
        /// DEFAULT ON since v0.4.0 (P3 gates passed) — pass `--graft false` for a baseline run.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
        graft: bool,
        /// Banked B0 GPU offload lever (requires a `--features gpu` build).
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
        gpu_subtree: bool,
        /// v0.4 Plan B lever: batch-affine Orchard combine (the SIMD bet leg).
        /// DEFAULT ON since v0.4.0 — pass `--batch-combine false` for a baseline run.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
        batch_combine: bool,
        /// v0.5 scan-pacer lever: derive chunk-boundary treestates locally
        /// (one seed fetch per range instead of one GetTreeState round-trip
        /// per boundary — P1 measured those at 62% of the Mac scan wall).
        /// Default OFF until the A/B + audit gates.
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
        local_treestate: bool,
        /// Boundary-audit cadence for --local-treestate: every Nth local
        /// boundary also fetches the server treestate OFF the critical path
        /// and compares (0 = off, 1 = audit EVERY boundary). Default 1.
        #[arg(long, default_value_t = 1)]
        treestate_verify_sample: u32,
        /// Write-behind queue depth (see `sync --persist-depth`). Default 1.
        #[arg(long, default_value_t = 1, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=64))]
        persist_depth: usize,
        /// Task 10 audit cadence: build-and-verify every Nth graftable shard
        /// against the server root (0 = off, 1 = audit EVERY graft — the
        /// validation mode). Default matches the engine (16).
        #[arg(long, default_value_t = 16)]
        graft_verify_sample: u32,
        /// Write the BenchSummary JSON here (default: <wallet_dir>/bench.json).
        #[arg(long)]
        json: Option<std::path::PathBuf>,
        /// Keep the wallet dir afterwards (temp dirs are deleted by default).
        #[arg(long, default_value_t = false)]
        keep: bool,
    },
    /// [API v2 Phase C acceptance] Live wallet console rendered ONLY from the v2 contract:
    /// the derived engine snapshot (state/permille/recovering/stalled), the engine-owned SQL
    /// views (`ext_slipstream_v_recovery_balance`, `ext_slipstream_v_tx_reconciled`), and the two
    /// DOCUMENTED one-line host rules (balance = recovering ? view : upstream summary;
    /// visible = reconciled OR NOT recovering). ZERO wallet math lives in this command — if
    /// it ever needs any, the engine API is wrong and must grow instead (ENGINE_API_V2.md §8).
    Watch {
        /// Network the wallet database belongs to.
        #[arg(long, value_enum, default_value_t = NetworkArg::Main)]
        network: NetworkArg,
        /// lightwalletd URL, e.g. <https://zec.rocks:443>
        #[arg(long)]
        server: String,
        /// Wallet directory (data.db lives inside).
        #[arg(long)]
        wallet_dir: std::path::PathBuf,
        /// UFVK to import on first run (fresh restore demo).
        #[arg(long)]
        ufvk: Option<String>,
        /// Birthday height for --ufvk import.
        #[arg(long)]
        birthday: Option<u64>,
        /// Render interval in milliseconds (min 200).
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
    },
    /// Golden-oracle run: sync the same UFVK/birthday twice into two wallet dirs
    /// (A = upstream persistence, B = upstream until T6.3 lands --sparse-b),
    /// then semantically diff the resulting data.db files. Exit 0 = identical.
    Oracle {
        /// Network the wallet databases belong to.
        #[arg(long, value_enum, default_value_t = NetworkArg::Main)]
        network: NetworkArg,
        #[arg(long)]
        server: String,
        /// Wallet dir A (created; must not contain data.db).
        #[arg(long)]
        wallet_a: std::path::PathBuf,
        /// Wallet dir B (created; must not contain data.db).
        #[arg(long)]
        wallet_b: std::path::PathBuf,
        #[arg(long)]
        ufvk: String,
        #[arg(long)]
        birthday: u64,
        /// Run B with sparse persistence (T6.3+).
        #[arg(long, default_value_t = false)]
        sparse_b: bool,
        /// T6.9: run B with write-behind pipelining as well (requires --sparse-b).
        #[arg(long, default_value_t = false)]
        write_behind_b: bool,
        /// B0 (Phase B): run B with the GPU Orchard subtree build (requires --sparse-b and a
        /// build with `--features gpu`). The acceptance gate: oracle VERDICT IDENTICAL.
        #[arg(long, default_value_t = false)]
        gpu_subtree_b: bool,
        /// Run B with a deeper write-behind queue (persist-pipelining). 1 = depth-1. The oracle
        /// proves any depth is byte-identical (VERDICT IDENTICAL vs the upstream run A).
        #[arg(long, default_value_t = 1, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=64))]
        persist_depth_b: usize,
        #[arg(long, default_value_t = 4, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
        streams: usize,
        #[arg(long, default_value_t = 10_000)]
        chunk: u32,
    },
}

/// Network selector shared by the wallet-touching subcommands. Defaults to
/// mainnet everywhere except `derive-ufvk` (fixture tooling).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum NetworkArg {
    /// Zcash mainnet.
    Main,
    /// Zcash testnet (including compatible custom testnets, e.g. the Ironwood
    /// testnet — the network selects key encodings/consensus parameters; the
    /// chain served is whatever the --server endpoint speaks).
    Test,
}

impl NetworkArg {
    fn to_network(self) -> zodl_slipstream::Network {
        match self {
            NetworkArg::Main => zodl_slipstream::Network::MainNetwork,
            NetworkArg::Test => zodl_slipstream::Network::TestNetwork,
        }
    }

    fn to_network_type(self) -> zcash_protocol::consensus::NetworkType {
        match self {
            NetworkArg::Main => zcash_protocol::consensus::NetworkType::Main,
            NetworkArg::Test => zcash_protocol::consensus::NetworkType::Test,
        }
    }
}

/// [IW-0.5] Resolve the sync network: stock params, or — when `--custom-heights`
/// is given — the selected constants with the parsed activation schedule.
fn resolve_network(
    arg: NetworkArg,
    custom_heights: Option<&str>,
) -> zodl_slipstream::SlipstreamNetwork {
    match custom_heights {
        None => arg.to_network().into(),
        Some(spec) => {
            let heights = parse_custom_heights(spec).unwrap_or_else(|e| {
                eprintln!("error: --custom-heights: {e}");
                std::process::exit(2);
            });
            zodl_slipstream::SlipstreamNetwork::Custom {
                constants: arg.to_network_type(),
                heights,
            }
        }
    }
}

/// Parse `--custom-heights` (see the Sync arg doc for the grammar).
fn parse_custom_heights(spec: &str) -> Result<zodl_slipstream::CustomActivations, String> {
    let mut h = zodl_slipstream::CustomActivations::default();
    for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if part == "genesis" {
            h = zodl_slipstream::CustomActivations::all_from_genesis();
            continue;
        }
        let (key, val) = part
            .split_once('=')
            .ok_or_else(|| format!("expected upgrade=height, got {part:?}"))?;
        let height: u32 = val
            .trim()
            .parse()
            .map_err(|e| format!("bad height in {part:?}: {e}"))?;
        let slot = match key.trim() {
            "overwinter" => &mut h.overwinter,
            "sapling" => &mut h.sapling,
            "blossom" => &mut h.blossom,
            "heartwood" => &mut h.heartwood,
            "canopy" => &mut h.canopy,
            "nu5" => &mut h.nu5,
            "nu6" => &mut h.nu6,
            "nu6_1" => &mut h.nu6_1,
            "nu6_2" => &mut h.nu6_2,
            other => return Err(format!("unknown upgrade {other:?}")),
        };
        *slot = Some(height);
    }
    Ok(h)
}

/// Derive and print the UFVK for a BIP-39 mnemonic (see `DeriveUfvk`).
fn cmd_derive_ufvk(mnemonic: &str, account: u32, network: zodl_slipstream::Network) {
    let parsed = bip39::Mnemonic::parse(mnemonic).unwrap_or_else(|e| {
        eprintln!("error: invalid mnemonic: {e}");
        std::process::exit(2);
    });
    let seed = parsed.to_seed("");
    let account_id = zip32::AccountId::try_from(account).unwrap_or_else(|_| {
        eprintln!("error: invalid account index {account}");
        std::process::exit(2);
    });
    let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(&network, &seed, account_id)
        .unwrap_or_else(|e| {
            eprintln!("error: derivation failed: {e:?}");
            std::process::exit(2);
        });
    println!("{}", usk.to_unified_full_viewing_key().encode(&network));
    eprintln!(
        "hint: slipstream sync --network {} --server <lwd-url> --wallet-dir <dir> --ufvk '<above>' --birthday <height>",
        match network {
            zodl_slipstream::Network::MainNetwork => "main",
            zodl_slipstream::Network::TestNetwork => "test",
        }
    );
}

fn parse_server(s: &str) -> Result<zodl_slipstream::Endpoint, String> {
    let (tls, rest) = if let Some(r) = s.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = s.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!("server must start with http:// or https://: {s}"));
    };
    let (host, port) = rest
        .trim_end_matches('/')
        .split_once(':')
        .ok_or_else(|| format!("server must include a port: {s}"))?;
    Ok(zodl_slipstream::Endpoint {
        host: host.to_string(),
        port: port.parse().map_err(|e| format!("bad port: {e}"))?,
        tls,
    })
}

fn parse_range(s: &str) -> Result<(u64, u64), String> {
    if s.contains("..=") {
        return Err(format!("range must be start..end (not ..=): {s}"));
    }
    let (a, b) = s
        .split_once("..")
        .ok_or_else(|| format!("range must be start..end: {s}"))?;
    let start: u64 = a.trim().parse().map_err(|e| format!("bad start: {e}"))?;
    let end: u64 = b.trim().parse().map_err(|e| format!("bad end: {e}"))?;
    if end < start {
        return Err("range end must be >= start".into());
    }
    Ok((start, end))
}

async fn run_fetch_bench(
    endpoint: &zodl_slipstream::Endpoint,
    start: u64,
    end: u64,
    chunk: u32,
    streams: usize,
) -> Result<zodl_slipstream::fetch::FetchStats, zodl_slipstream::SlipstreamError> {
    let (tx, mut rx) = zodl_slipstream::chunk::chunk_queue(256 * 1024 * 1024);
    let drain = tokio::spawn(async move { while let Some((_c, _p, _b)) = rx.recv().await {} });
    let plan = zodl_slipstream::fetch::FetchPlan::new(start, end, chunk, streams);
    let stats = zodl_slipstream::fetch::run_fetch(endpoint, plan, tx, None).await?;
    let _ = drain.await;
    Ok(stats)
}

/// [v0.7 P0] Run the weather machine until Ctrl-C: local plain-TCP proxy
/// with a shared bandwidth cap in front of a lightwalletd. Point the engine
/// at the printed address with `http://` (tls=false).
fn cmd_throttle_proxy(
    target: String,
    listen: u16,
    cap_kbps: u64,
    collapse_after_s: u64,
    collapse_to_kbps: u64,
) {
    use std::net::ToSocketAddrs as _;

    let target_addr = target
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .unwrap_or_else(|| {
            eprintln!("cannot resolve --target '{target}' (expected host:port)");
            std::process::exit(2);
        });
    let cap = if cap_kbps == 0 {
        zodl_slipstream::throttle::UNCAPPED
    } else {
        cap_kbps * 1024
    };
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        let proxy = zodl_slipstream::throttle::ThrottleProxy::start(listen, target_addr, cap)
            .await
            .expect("start throttle proxy");
        println!(
            "weather machine up: http://{} -> {} (cap {})",
            proxy.local_addr(),
            target_addr,
            if cap_kbps == 0 {
                "uncapped".to_string()
            } else {
                format!("{cap_kbps} KB/s")
            },
        );
        println!(
            "point the engine at it, e.g.: --server http://{}",
            proxy.local_addr()
        );
        if collapse_after_s > 0 {
            println!("scripted collapse: to {collapse_to_kbps} KB/s after {collapse_after_s} s");
            tokio::time::sleep(std::time::Duration::from_secs(collapse_after_s)).await;
            proxy.set_cap(collapse_to_kbps * 1024);
            println!("collapse fired: cap now {collapse_to_kbps} KB/s");
        }
        std::future::pending::<()>().await; // Ctrl-C terminates the process
    });
}

fn cmd_fetch(server: String, range: String, streams: usize, chunk: u32, baseline: bool) {
    let endpoint = parse_server(&server).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    let (start, end) = parse_range(&range).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let mut base_stats = None;
        if baseline {
            println!("baseline run (streams=1)...");
            match run_fetch_bench(&endpoint, start, end, chunk, 1).await {
                Ok(s) => {
                    println!(
                        "  K=1: {} blocks, {:.1} MB, {:.1}s, {:.0} blk/s, {:.2} MB/s",
                        s.blocks,
                        s.bytes as f64 / 1048576.0,
                        s.elapsed.as_secs_f64(),
                        s.blocks_per_sec(),
                        s.megabytes_per_sec()
                    );
                    base_stats = Some(s);
                }
                Err(e) => {
                    eprintln!("baseline failed: {e}");
                    std::process::exit(1)
                }
            }
        }
        println!("measured run (streams={streams})...");
        match run_fetch_bench(&endpoint, start, end, chunk, streams).await {
            Ok(s) => {
                println!(
                    "  K={streams}: {} blocks, {:.1} MB, {:.1}s, {:.0} blk/s, {:.2} MB/s",
                    s.blocks,
                    s.bytes as f64 / 1048576.0,
                    s.elapsed.as_secs_f64(),
                    s.blocks_per_sec(),
                    s.megabytes_per_sec()
                );
                if let Some(b) = base_stats {
                    println!(
                        "  speedup vs K=1: {:.2}x",
                        s.megabytes_per_sec() / b.megabytes_per_sec()
                    );
                }
            }
            Err(e) => {
                eprintln!("fetch failed: {e}");
                std::process::exit(1)
            }
        }
    });
}

// ── `watch` (API v2 Phase C acceptance) ────────────────────────────────────────────────────

fn event_tag_name(tag: u8) -> &'static str {
    match tag {
        1 => "SyncStarted",
        2 => "SyncProgress",
        3 => "SyncDone",
        4 => "SyncError",
        5 => "FoundTransactions",
        _ => "Unknown",
    }
}

/// Display formatting only (integer split — no wallet math).
fn zec_display(zat: i64) -> String {
    let sign = if zat < 0 { "-" } else { "" };
    let a = zat.unsigned_abs();
    format!("{sign}{}.{:08}", a / 100_000_000, a % 100_000_000)
}

fn uuid_prefix(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// The Phase C acceptance harness: renders wallet state ONLY from the v2 contract.
/// If this function ever needs wallet math, the engine API is wrong (ENGINE_API_V2.md §8).
fn cmd_watch(
    network: zodl_slipstream::Network,
    server: String,
    wallet_dir: std::path::PathBuf,
    ufvk: Option<String>,
    birthday: Option<u64>,
    interval_ms: u64,
) {
    let endpoint = parse_server(&server).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    let accounts = validate_sync_args(&network, ufvk.as_deref(), birthday).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(2)
    });
    let db_path = wallet_dir.join("data.db");
    let cfg = zodl_slipstream::EngineConfig::new(network, db_path.clone(), endpoint);

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        let reporter = zodl_slipstream::SessionReporter {
            progress: std::sync::Arc::new(zodl_slipstream::Progress::default()),
            state: std::sync::Arc::new(std::sync::Mutex::new(
                zodl_slipstream::ffi_handle::SyncState::Idle,
            )),
            events: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        // [API v2.1 E-3] Truthful-from-open: seed the snapshot atomics from the persisted
        // wallet (same call the iOS FFI open() makes) — the SECOND-HOST acceptance proof
        // that no host needs pre-first-suggest compensation. Failure = cold snapshot.
        if let Ok(session) =
            zodl_slipstream::wallet_session::WalletSession::open(network, &db_path)
            && let Err(e) =
                zodl_slipstream::scheduler::seed_progress_from_wallet(&reporter.progress, &session)
            {
                eprintln!("warn: E-3 open-time snapshot seed failed ({e}) — starting cold");
            }
        let scfg = zodl_slipstream::SessionConfig {
            engine: cfg,
            accounts,
            tor: None,
        };
        let session = tokio::spawn(zodl_slipstream::session::run_session(
            scfg,
            reporter.clone(),
            std::sync::Arc::new(tokio::sync::Mutex::new(())),
        ));

        println!("watch: rendering from the v2 contract only (derived snapshot + engine views). Ctrl-C to stop.");
        let mut interval =
            tokio::time::interval(std::time::Duration::from_millis(interval_ms.max(200)));
        loop {
            interval.tick().await;

            // v2 channel 1: the derived snapshot — the SAME derivation the FFI serves
            // (fail-safe recovery latch, monotonic permille, stall clock included).
            let state = *reporter.state.lock().unwrap_or_else(|p| p.into_inner());
            let snap = zodl_slipstream::ffi_handle::derive_snapshot(&reporter.progress, state);

            // Edge signals: drain + print.
            let drained: Vec<zodl_slipstream::ffi_handle::FfiSlipstreamEvent> = {
                let mut ring = reporter.events.lock().unwrap_or_else(|p| p.into_inner());
                std::mem::take(&mut *ring)
            };
            for e in &drained {
                println!("event: {} (value {})", event_tag_name(e.tag), e.value);
            }

            // v2 channel 2 — the DOCUMENTED host rules, verbatim:
            //   balance = is_recovering ? SELECT ext_slipstream_v_recovery_balance : upstream summary
            let balances: Vec<(String, i64, &'static str)> = if snap.is_recovering == 1 {
                // [issue #4] The view read lives in zodl-slipstream (`reconcile`);
                // the CLI holds only the short read connection.
                let mut out = Vec::new();
                if let Ok(conn) = rusqlite::Connection::open(&db_path) {
                    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
                    if let Ok(rows) = zodl_slipstream::reconcile::recovery_balances(&conn) {
                        for (uuid, zat) in rows {
                            out.push((uuid_prefix(&uuid), zat, "Σ reconciled (recovering)"));
                        }
                    }
                }
                out
            } else {
                use zcash_client_backend::data_api::WalletRead;
                match zcash_client_sqlite::WalletDb::for_path(
                    &db_path,
                    network,
                    zcash_client_sqlite::util::SystemClock,
                    rand::rngs::OsRng,
                ) {
                    Ok(db) => match db.get_wallet_summary(
                        zcash_client_backend::data_api::wallet::ConfirmationsPolicy::default(),
                    ) {
                        Ok(Some(summary)) => summary
                            .account_balances()
                            .iter()
                            .map(|(uuid, b)| {
                                (
                                    uuid_prefix(uuid.expose_uuid().as_bytes()),
                                    i64::try_from(u64::from(b.total())).unwrap_or(i64::MAX),
                                    "upstream summary",
                                )
                            })
                            .collect(),
                        _ => Vec::new(),
                    },
                    Err(_) => Vec::new(),
                }
            };

            //   visible = reconciled OR NOT is_recovering (mined txs only)
            // [issue #4] Served entirely by the slipstream-owned view via
            // zodl-slipstream (`reconcile`) — no hand-rolled SQL here.
            let visible: i64 = rusqlite::Connection::open(&db_path)
                .ok()
                .and_then(|conn| {
                    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
                    zodl_slipstream::reconcile::visible_mined_tx_count(
                        &conn,
                        snap.is_recovering == 1,
                    )
                    .ok()
                })
                .map_or(-1, |n| i64::try_from(n).unwrap_or(i64::MAX));

            let state_name = match snap.state {
                0 => "idle",
                1 => "syncing",
                2 => "error",
                3 => "done",
                _ => "?",
            };
            let bal_str = if balances.is_empty() {
                "balance: (none yet)".to_string()
            } else {
                balances
                    .iter()
                    .map(|(u, z, src)| format!("{u}: {} ZEC [{src}]", zec_display(*z)))
                    .collect::<Vec<_>>()
                    .join(" | ")
            };
            println!(
                "[{state_name}] {}‰ | recovering: {} | stalled: {}s | scanned {}/{} | tip {} | visible txs: {} | {}",
                snap.progress_permille,
                snap.is_recovering == 1,
                snap.stalled_seconds,
                snap.scanned_blocks,
                snap.pass_total_blocks,
                snap.chain_tip,
                visible,
                bal_str
            );

            if session.is_finished() {
                eprintln!("watch: session ended (non-transient initial error) — see logs above");
                std::process::exit(1);
            }
        }
    });
}

/// Decode a `--ufvk` string + `--birthday` height into the engine's typed account tuple.
/// Decoding lives at the CLI boundary so the engine only ever handles parsed keys.
fn parse_account<P: Parameters>(
    network: &P,
    ufvk: &str,
    birthday: u64,
) -> Result<(UnifiedFullViewingKey, BlockHeight), String> {
    let ufvk =
        UnifiedFullViewingKey::decode(network, ufvk).map_err(|e| format!("invalid --ufvk: {e}"))?;
    let birthday = u32::try_from(birthday)
        .map_err(|_| format!("--birthday {birthday} exceeds the u32 block-height range"))?;
    Ok((ufvk, BlockHeight::from_u32(birthday)))
}

/// Resolve the `--ufvk`/`--birthday` pair into the account list `sync_once` bootstraps.
/// Returns an empty list when no key is supplied (a keyless pass over an existing wallet).
fn validate_sync_args<P: Parameters>(
    network: &P,
    ufvk: Option<&str>,
    birthday: Option<u64>,
) -> Result<Vec<(UnifiedFullViewingKey, BlockHeight)>, String> {
    match (ufvk, birthday) {
        (Some(u), Some(b)) => Ok(vec![parse_account(network, u, b)?]),
        (None, None) => Ok(Vec::new()),
        (Some(_), None) => {
            Err("--ufvk requires --birthday: provide the wallet birthday height".into())
        }
        (None, Some(_)) => {
            // birthday without ufvk is silently ignored (may be used with an existing wallet)
            Ok(Vec::new())
        }
    }
}

/// Guard: `--gpu-subtree[-b]` is meaningless unless the binary was built with
/// `--features gpu`. Without it the GPU routing falls back to the CPU path — which for
/// the oracle would be a FALSE `VERDICT IDENTICAL`. Fail loudly instead of silently.
fn require_gpu_feature_if(requested: bool, flag: &str) {
    if requested && !cfg!(feature = "gpu") {
        eprintln!(
            "error: {flag} needs a build with --features gpu (else it silently runs the CPU \
             path — a false IDENTICAL). Rebuild, e.g.: cargo run -p slipstream-cli --features gpu -- …"
        );
        std::process::exit(2);
    }
}

/// v0.4 P0 (spec §3.3): fresh-restore benchmark. One measured pass, honest by
/// construction: refuses a pre-populated wallet dir (that would be a catch-up,
/// not a restore) and prints/persists the engine-written BenchSummary.
#[allow(clippy::too_many_arguments)]
fn cmd_bench(
    network: zodl_slipstream::Network,
    server: String,
    alternate_server: Vec<String>,
    ufvk: String,
    birthday: u64,
    wallet_dir: Option<std::path::PathBuf>,
    graft: bool,
    gpu_subtree: bool,
    batch_combine: bool,
    local_treestate: bool,
    treestate_verify_sample: u32,
    persist_depth: usize,
    graft_verify_sample: u32,
    json: Option<std::path::PathBuf>,
    keep: bool,
) {
    let endpoint = parse_server(&server).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    require_gpu_feature_if(gpu_subtree, "--gpu-subtree");

    // Wallet dir: user-supplied (must be fresh) or a temp dir (deleted unless --keep).
    let (dir, tempdir_guard) = match wallet_dir {
        Some(d) => {
            if d.join("data.db").exists() {
                eprintln!(
                    "error: {} already contains a data.db — a bench is a FRESH restore; \
                     point --wallet-dir at an empty dir or omit it for a temp dir",
                    d.display()
                );
                std::process::exit(2);
            }
            std::fs::create_dir_all(&d).unwrap_or_else(|e| {
                eprintln!("error: create {}: {e}", d.display());
                std::process::exit(2)
            });
            (d, None)
        }
        None => {
            let td = tempfile::tempdir().unwrap_or_else(|e| {
                eprintln!("error: tempdir: {e}");
                std::process::exit(2)
            });
            (td.path().to_path_buf(), Some(td))
        }
    };

    let json_path = json.unwrap_or_else(|| dir.join("bench.json"));
    let mut cfg = zodl_slipstream::EngineConfig::new(network, dir.join("data.db"), endpoint);
    cfg.gpu_subtree = gpu_subtree;
    // v0.4 Plan A lever (Task 8+): live A/B switch — the whole point of bench.
    cfg.graft_subtree = graft;
    cfg.local_treestate = local_treestate;
    cfg.treestate_verify_sample = treestate_verify_sample;
    cfg.persist_depth = persist_depth;
    cfg.graft_verify_sample = graft_verify_sample;
    cfg.batch_combine = batch_combine;
    cfg.alternate_endpoints = alternate_server
        .iter()
        .map(|a| {
            parse_server(a).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(2)
            })
        })
        .collect();
    let accounts = vec![
        parse_account(&network, &ufvk, birthday).unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(2)
        }),
    ];

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let outcome = rt.block_on(async {
        let progress = std::sync::Arc::new(zodl_slipstream::Progress::default());
        let ticker_progress = std::sync::Arc::clone(&progress);
        let ticker = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
            interval.tick().await;
            loop {
                interval.tick().await;
                println!(
                    "progress: fetched {} | scanned {} | enhanced {} (tip {})",
                    ticker_progress.fetched(),
                    ticker_progress.scanned(),
                    ticker_progress.enhanced(),
                    ticker_progress.chain_tip()
                );
            }
        });
        let result =
            zodl_slipstream::engine::sync_once(&cfg, &accounts, Some(progress), None).await;
        ticker.abort();
        result
    });

    let outcome = outcome.unwrap_or_else(|e| {
        eprintln!("bench failed: {e}");
        std::process::exit(1)
    });

    // The engine no longer presents the pass itself — emit its tracing summary here.
    zodl_slipstream::report::log_pass_summary(&outcome, &cfg);

    // Human table — same numbers as the JSON artifact written below.
    let r = &outcome.report;
    let wait_s = r.persist_wait_elapsed.as_secs_f64();
    let busy_s = r.persist_busy_elapsed.as_secs_f64();
    println!();
    println!(
        "bench: total {:.1}s | fetch {:.1}s | scan {:.1}s | enhance {:.1}s | persist_wait {:.1}s | overlap {:.1}s",
        outcome.elapsed.as_secs_f64(),
        r.fetch_elapsed.as_secs_f64(),
        r.scan_elapsed.as_secs_f64(),
        outcome.enhance_elapsed.as_secs_f64(),
        wait_s,
        (busy_s - wait_s).max(0.0),
    );
    for (label, c) in [
        ("sapling", &r.census_sapling),
        ("orchard", &r.census_orchard),
    ] {
        println!(
            "census {label}: shards {} | noted {} | graftable {:.0}%",
            c.shards(),
            c.noted_shards(),
            c.graftable_fraction() * 100.0
        );
    }
    println!(
        "Plan A ceiling (orchard, the dominant combine cost): skip ~{:.0}% of shard builds on this wallet",
        r.census_orchard.graftable_fraction() * 100.0
    );
    match zodl_slipstream::report::bench_summary(&outcome).write_json(&json_path) {
        Ok(()) => println!("json: {}", json_path.display()),
        Err(e) => eprintln!(
            "warning: bench JSON write failed at {}: {e}",
            json_path.display()
        ),
    }
    match (tempdir_guard, keep) {
        (Some(td), true) => {
            // Leak deliberately: --keep promotes the temp dir to a kept artifact.
            let path = td.keep();
            println!("wallet dir kept: {}", path.display());
        }
        (Some(_td), false) => {} // dropped → deleted
        (None, _) => println!("wallet dir: {}", dir.display()),
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_sync(
    network: zodl_slipstream::SlipstreamNetwork,
    server: String,
    wallet_dir: std::path::PathBuf,
    ufvk: Option<String>,
    birthday: Option<u64>,
    streams: usize,
    chunk: u32,
    sparse: bool,
    chunk_split_bytes: usize,
    memory_budget_bytes: usize,
    write_behind: bool,
    gpu_subtree: bool,
    persist_depth: usize,
    follow: bool,
    anchor_retention: Option<u32>,
    anchor_retention_interval: u32,
) {
    let endpoint = parse_server(&server).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });

    if ufvk.is_none() && birthday.is_some() {
        eprintln!("note: --birthday without --ufvk is ignored (no import will occur)");
    }

    let accounts = validate_sync_args(&network, ufvk.as_deref(), birthday).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(2)
    });

    let mut cfg = zodl_slipstream::EngineConfig::new(network, wallet_dir.join("data.db"), endpoint);
    cfg.fetch_streams = streams;
    cfg.chunk_blocks = chunk;
    cfg.sparse_persistence = sparse;
    cfg.chunk_split_bytes = chunk_split_bytes;
    cfg.memory_budget_bytes = memory_budget_bytes;
    // [B6] The floor and the grid together are the retention policy; an interval
    // of zero is not a grid, so it is rejected rather than silently defaulted.
    cfg.anchor_retention = match anchor_retention {
        Some(floor) => {
            let Some(blocks) = std::num::NonZeroU32::new(anchor_retention_interval) else {
                eprintln!("error: --anchor-retention-interval must be greater than zero");
                std::process::exit(2)
            };
            Some(zodl_slipstream::AnchorRetention::new(
                zcash_protocol::consensus::BlockHeight::from(floor),
                zodl_slipstream::AnchorRetentionInterval::custom(blocks),
            ))
        }
        None => None,
    };
    require_gpu_feature_if(gpu_subtree, "--gpu-subtree");
    // `--sparse false` (the sparse kill switch) implies write-behind off: the
    // deferred commit runs the sparse put_blocks path, so it cannot outlive it.
    cfg.write_behind = write_behind && sparse;
    cfg.gpu_subtree = gpu_subtree && sparse;
    // Same rule for the graft (default ON since v0.4): its verdict lives in the
    // sparse build path, so the sparse kill switch implies graft off.
    cfg.graft_subtree = cfg.graft_subtree && sparse;
    cfg.persist_depth = persist_depth;

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        // Build shared progress state for the CLI ticker (decision D8 poll-based).
        let progress = std::sync::Arc::new(zodl_slipstream::Progress::default());
        let ticker_progress = std::sync::Arc::clone(&progress);

        // Spawn a 2-second ticker task that prints one line per tick.
        // Plain println lines (no \r tricks — some terminals do not support them).
        // The task is aborted (not joined) after sync_once returns.
        let ticker = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;
                let fetched = ticker_progress.fetched();
                let scanned = ticker_progress.scanned();
                let enhanced = ticker_progress.enhanced();
                let tip = ticker_progress.chain_tip();
                println!(
                    "progress: fetched {} | scanned {} | enhanced {} (tip {})",
                    fetched, scanned, enhanced, tip
                );
            }
        });

        // --follow: run the FULL autonomous engine session (import if --ufvk, resilient initial
        // pass, then tip-following + mempool) via zodl_slipstream::session::run_session — the
        // SAME orchestration the FFI uses. Observability = the ticker above + the engine's own
        // tracing (the "sync stage split" lines). Runs until Ctrl-C; returns only on a
        // non-transient initial error. Replaces the old bespoke loop (which exited on any
        // follow-pass blip — the exact resilience hazard the lift removes).
        if follow {
            let scfg = zodl_slipstream::SessionConfig {
                engine: cfg.clone(),
                accounts: accounts.clone(),
                tor: None,
            };
            let reporter = zodl_slipstream::SessionReporter {
                progress: std::sync::Arc::clone(&progress),
                state: std::sync::Arc::new(std::sync::Mutex::new(
                    zodl_slipstream::ffi_handle::SyncState::Done,
                )),
                events: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            };
            println!("follow: running autonomous engine session (Ctrl-C to stop) ...");
            zodl_slipstream::session::run_session(
                scfg,
                reporter,
                std::sync::Arc::new(tokio::sync::Mutex::new(())),
            )
            .await;
            ticker.abort();
            eprintln!("sync session ended: non-transient initial error (see logs above)");
            std::process::exit(1);
        }

        let result =
            zodl_slipstream::engine::sync_once(&cfg, &accounts, Some(progress), None).await;

        // Abort the ticker (JoinHandle::abort is fine per spec — no cleanup needed).
        ticker.abort();

        match result {
            Ok(outcome) => {
                // Engine returns a bare result; emit its tracing summary here
                // (the --follow path gets this via session::run_pass_with_retry).
                zodl_slipstream::report::log_pass_summary(&outcome, &cfg);
                let mb = outcome.report.fetch.bytes as f64 / 1_048_576.0;
                println!(
                    "synced to tip {} in {:.1}s",
                    outcome.chain_tip,
                    outcome.elapsed.as_secs_f64()
                );
                println!(
                    "ranges {} | fetched {} blocks ({:.1} MB) | scanned {} blocks",
                    outcome.report.ranges_processed,
                    outcome.report.fetch.blocks,
                    mb,
                    outcome.report.scan.blocks,
                );
                println!(
                    "notes found: sapling {} orchard {}",
                    outcome.report.scan.sapling_received, outcome.report.scan.orchard_received,
                );
                println!(
                    "enhanced: {} txs, {} statuses ({} skipped)",
                    outcome.enhance.txs_stored,
                    outcome.enhance.statuses_set,
                    outcome.enhance.skipped,
                );
                println!(
                    "utxos: {} across {} accounts",
                    outcome.transparent.utxos, outcome.transparent.accounts,
                );
                // Per-stage timing + bound (Decision-Log requirement for honest G5 reporting).
                println!(
                    "stages: fetch {:.1}s | scan {:.1}s | enhance {:.1}s (bound: {})",
                    outcome.report.fetch_elapsed.as_secs_f64(),
                    outcome.report.scan_elapsed.as_secs_f64(),
                    outcome.enhance_elapsed.as_secs_f64(),
                    outcome.bound(),
                );
                // T6.9 write-behind overlap quality (only printed when active).
                let pw = outcome.report.persist_wait_elapsed.as_secs_f64();
                let pb = outcome.report.persist_busy_elapsed.as_secs_f64();
                if pb > 0.0 {
                    println!(
                        "write-behind: persist busy {:.1}s | wait {:.1}s | overlap won {:.1}s",
                        pb,
                        pw,
                        (pb - pw).max(0.0),
                    );
                }
                // Reorg summary (only if any recoveries occurred).
                if outcome.report.reorgs_recovered > 0 {
                    println!("reorgs: {} recovered", outcome.report.reorgs_recovered);
                }
            }
            Err(e) => {
                eprintln!("sync failed: {e}");
                std::process::exit(1);
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn cmd_oracle(
    network: zodl_slipstream::Network,
    server: String,
    wallet_a: std::path::PathBuf,
    wallet_b: std::path::PathBuf,
    ufvk: String,
    birthday: u64,
    sparse_b: bool,
    write_behind_b: bool,
    gpu_subtree_b: bool,
    persist_depth_b: usize,
    streams: usize,
    chunk: u32,
) {
    let endpoint = parse_server(&server).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    if write_behind_b && !sparse_b {
        eprintln!("error: --write-behind-b requires --sparse-b");
        std::process::exit(2);
    }
    if gpu_subtree_b && !sparse_b {
        eprintln!("error: --gpu-subtree-b requires --sparse-b");
        std::process::exit(2);
    }
    require_gpu_feature_if(gpu_subtree_b, "--gpu-subtree-b");
    for d in [&wallet_a, &wallet_b] {
        if d.join("data.db").exists() {
            eprintln!(
                "error: {} already contains data.db — oracle needs fresh wallets",
                d.display()
            );
            std::process::exit(2);
        }
    }
    let mk_cfg = |dir: &std::path::Path,
                  sparse: bool,
                  write_behind: bool,
                  gpu_subtree: bool,
                  persist_depth: usize| {
        let mut cfg =
            zodl_slipstream::EngineConfig::new(network, dir.join("data.db"), endpoint.clone());
        cfg.fetch_streams = streams;
        cfg.chunk_blocks = chunk;
        cfg.sparse_persistence = sparse;
        cfg.write_behind = write_behind;
        cfg.gpu_subtree = gpu_subtree;
        cfg.persist_depth = persist_depth;
        cfg
    };
    let accounts = vec![
        parse_account(&network, &ufvk, birthday).unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(2)
        }),
    ];

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let verdict = rt.block_on(async {
        println!("oracle: run A (upstream persistence) …");
        let a = zodl_slipstream::engine::sync_once(&mk_cfg(&wallet_a, false, false, false, 1), &accounts, None, None).await?;
        println!("oracle: run A done — tip {} in {:.1?}", a.chain_tip, a.elapsed);
        println!("oracle: run B (sparse_b={sparse_b} write_behind_b={write_behind_b} gpu_subtree_b={gpu_subtree_b} persist_depth_b={persist_depth_b}) …");
        let b = zodl_slipstream::engine::sync_once(&mk_cfg(&wallet_b, sparse_b, write_behind_b, gpu_subtree_b, persist_depth_b), &accounts, None, None).await?;
        println!("oracle: run B done — tip {} in {:.1?}", b.chain_tip, b.elapsed);
        if a.chain_tip != b.chain_tip {
            eprintln!("oracle: TIP SKEW (A={} B={}) — rerun when the chain is quiet", a.chain_tip, b.chain_tip);
            std::process::exit(3);
        }
        zodl_slipstream::oracle::semantic_diff(&wallet_a.join("data.db"), &wallet_b.join("data.db"))
    });
    match verdict {
        Ok(report) => {
            print!("{}", report.render());
            if report.is_clean() {
                println!("oracle: VERDICT IDENTICAL");
            } else {
                println!("oracle: VERDICT DIVERGED");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("oracle failed: {e}");
            std::process::exit(1);
        }
    }
}

/// \[B7\] Propose, prove, and broadcast a spend from a synced wallet. The
/// proposal runs upstream's production shapes (greedy selector, ZIP-317
/// multi-output change, `SpendPolicy::default()` = every shielded pool the
/// chain has activated, Ironwood included), the transaction is proved with
/// orchard 0.15's pool-agnostic circuit, and the raw bytes are broadcast via
/// lightwalletd. Sapling provers are structurally required by the API but an
/// orchard/ironwood-only transaction never invokes them (the stub panics if
/// one ever were).
#[allow(clippy::too_many_arguments)]
fn cmd_send(
    network: zodl_slipstream::Network,
    server: String,
    wallet_dir: std::path::PathBuf,
    mnemonic: String,
    account: u32,
    to: Option<String>,
    zats: u64,
) {
    use std::num::{NonZeroU32, NonZeroUsize};
    use zcash_client_backend::data_api::WalletRead;
    use zcash_client_backend::data_api::wallet::{
        ConfirmationsPolicy, SpendingKeys, create_proposed_transactions,
        input_selection::GreedyInputSelector, propose_transfer,
    };
    use zcash_client_backend::fees::{
        DustOutputPolicy, SplitPolicy, StandardFeeRule, zip317::MultiOutputChangeStrategy,
    };
    use zcash_client_backend::wallet::OvkPolicy;
    use zcash_client_backend::zip321::{Payment, TransactionRequest};
    use zcash_protocol::{ShieldedPool, value::Zatoshis};

    let endpoint = match parse_server(&server) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };

    // Spending key from the mnemonic (same derivation as `derive-ufvk`).
    let parsed = bip39::Mnemonic::parse(&mnemonic).unwrap_or_else(|e| {
        eprintln!("error: invalid mnemonic: {e}");
        std::process::exit(2);
    });
    let seed = parsed.to_seed("");
    let account_id = zip32::AccountId::try_from(account).expect("account index");
    let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(&network, &seed, account_id)
        .expect("usk derivation");
    let ufvk = usk.to_unified_full_viewing_key();

    let mut session =
        zodl_slipstream::wallet_session::WalletSession::open(network, &wallet_dir.join("data.db"))
            .expect("open wallet db");
    let db = session.db_mut();
    let accounts = db.get_account_ids().expect("account ids");
    assert_eq!(
        accounts.len(),
        1,
        "send tooling expects a single-account wallet"
    );
    let wallet_account = accounts[0];

    // The derived key must be THE wallet's key (guards against wrong mnemonic/account).
    {
        use zcash_client_backend::data_api::Account as _;
        let acct = db
            .get_account(wallet_account)
            .expect("get account")
            .expect("account exists");
        let wallet_ufvk = acct.ufvk().expect("wallet has a UFVK").encode(&network);
        assert_eq!(
            wallet_ufvk,
            ufvk.encode(&network),
            "mnemonic/account does not match the wallet's UFVK"
        );
    }

    // Recipient: explicit --to, or the account's own unified address (self-send).
    let to_encoded = to.unwrap_or_else(|| {
        let (ua, _) = ufvk
            .default_address(zcash_keys::keys::UnifiedAddressRequest::AllAvailableKeys)
            .expect("default address");
        ua.encode(&network)
    });
    let addr = ::zcash_address::ZcashAddress::try_from_encoded(&to_encoded)
        .expect("recipient address parses");
    println!("to:     {to_encoded}");
    println!("amount: {zats} zats");

    let request = TransactionRequest::new(vec![
        Payment::new(
            addr,
            Some(Zatoshis::const_from_u64(zats)),
            None,
            None,
            None,
            vec![],
        )
        .expect("payment"),
    ])
    .expect("transaction request");

    // Production's exact selector + change shapes (rust/src/lib.rs zip317_helper);
    // Ironwood-spend change routes to Ironwood outputs upstream, the fallback
    // pool only applies where no better rule fires.
    let change_strategy = MultiOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Orchard,
        DustOutputPolicy::default(),
        SplitPolicy::with_min_output_value(
            NonZeroUsize::new(4).expect("nonzero"),
            Zatoshis::const_from_u64(10_000_000),
        ),
    );
    let input_selector = GreedyInputSelector::new();

    let proposal = propose_transfer::<_, _, _, _, std::convert::Infallible>(
        db,
        &network,
        wallet_account,
        &input_selector,
        &change_strategy,
        request,
        ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, true),
        &zcash_client_backend::data_api::wallet::input_selection::SpendPolicy::default(),
        None,
        None,
    )
    .expect("propose_transfer");
    for (i, step) in proposal.steps().iter().enumerate() {
        println!("step {i}: balance {:?}", step.balance());
    }

    // Sapling provers: structurally required, never invoked for orchard/ironwood-only
    // (exact stubs from the engine's darkside oracle graft_spend_proof).
    struct NoSapling;
    impl sapling::prover::SpendProver for NoSapling {
        type Proof = ();
        fn prepare_circuit(
            _: sapling::ProofGenerationKey,
            _: sapling::Diversifier,
            _: sapling::Rseed,
            _: sapling::value::NoteValue,
            _: jubjub::Fr,
            _: sapling::value::ValueCommitTrapdoor,
            _: bls12_381::Scalar,
            _: sapling::MerklePath,
        ) -> Option<sapling::circuit::Spend> {
            unreachable!("orchard/ironwood-only tx must not prepare sapling spends")
        }
        fn create_proof<R: rand::RngCore>(
            &self,
            _: sapling::circuit::Spend,
            _: &mut R,
        ) -> Self::Proof {
            unreachable!("orchard/ironwood-only tx must not prove sapling spends")
        }
        fn encode_proof(_: Self::Proof) -> sapling::bundle::GrothProofBytes {
            unreachable!("orchard/ironwood-only tx must not encode sapling spend proofs")
        }
    }
    impl sapling::prover::OutputProver for NoSapling {
        type Proof = ();
        fn prepare_circuit(
            _: &sapling::keys::EphemeralSecretKey,
            _: sapling::PaymentAddress,
            _: jubjub::Fr,
            _: sapling::value::NoteValue,
            _: sapling::value::ValueCommitTrapdoor,
        ) -> sapling::circuit::Output {
            unreachable!("orchard/ironwood-only tx must not prepare sapling outputs")
        }
        fn create_proof<R: rand::RngCore>(
            &self,
            _: sapling::circuit::Output,
            _: &mut R,
        ) -> Self::Proof {
            unreachable!("orchard/ironwood-only tx must not prove sapling outputs")
        }
        fn encode_proof(_: Self::Proof) -> sapling::bundle::GrothProofBytes {
            unreachable!("orchard/ironwood-only tx must not encode sapling output proofs")
        }
    }

    println!("proving + creating transaction (orchard circuit, pool-agnostic)...");
    let txids = create_proposed_transactions::<
        _,
        _,
        std::convert::Infallible,
        _,
        std::convert::Infallible,
        _,
    >(
        db,
        &network,
        &NoSapling,
        &NoSapling,
        &SpendingKeys::from_unified_spending_key(usk),
        OvkPolicy::Sender,
        &proposal,
        None,
    )
    .expect("create_proposed_transactions");
    assert_eq!(txids.len(), 1, "exactly one transaction expected");
    let txid = *txids.first();
    println!("txid:   {txid}");

    let tx = db
        .get_transaction(txid)
        .expect("read created tx")
        .expect("created tx present");
    let mut raw = Vec::new();
    tx.write(&mut raw).expect("serialize tx");
    println!("raw:    {} bytes", raw.len());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let (code, message) = rt
        .block_on(async {
            let mut client = zodl_slipstream::grpc::connect(&endpoint).await?;
            zodl_slipstream::grpc::send_transaction(&mut client, raw).await
        })
        .expect("broadcast");
    if code == 0 {
        println!("BROADCAST ACCEPTED: txid {txid}");
    } else {
        println!("BROADCAST REJECTED ({code}): {message}");
        std::process::exit(1);
    }
}

fn main() {
    // v0.6 P6: `zcash_client_backend=warn` silences upstream's per-block
    // INFO spans (`#[instrument]` on add_block + scan_block_with_runners =
    // ~600k span creations + fmt-layer field formatting per restore, all on
    // the producer thread — named by the Mac profile). RUST_LOG overrides.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,zcash_client_backend=warn".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Version => {
            println!(
                "{} {}",
                zodl_slipstream::CRATE_NAME,
                env!("CARGO_PKG_VERSION")
            );
        }
        Cmd::ThrottleProxy {
            target,
            listen,
            cap_kbps,
            collapse_after_s,
            collapse_to_kbps,
        } => {
            cmd_throttle_proxy(target, listen, cap_kbps, collapse_after_s, collapse_to_kbps);
        }
        Cmd::Fetch {
            server,
            range,
            streams,
            chunk,
            baseline,
        } => {
            cmd_fetch(server, range, streams, chunk, baseline);
        }
        Cmd::DeriveUfvk {
            mnemonic,
            account,
            network,
        } => {
            cmd_derive_ufvk(&mnemonic, account, network.to_network());
        }
        Cmd::Send {
            network,
            server,
            wallet_dir,
            mnemonic,
            account,
            to,
            zats,
        } => {
            cmd_send(
                network.to_network(),
                server,
                wallet_dir,
                mnemonic,
                account,
                to,
                zats,
            );
        }
        Cmd::Sync {
            network,
            custom_heights,
            server,
            wallet_dir,
            ufvk,
            birthday,
            streams,
            chunk,
            sparse,
            anchor_retention,
            anchor_retention_interval,
            chunk_split_bytes,
            memory_budget_bytes,
            write_behind,
            gpu_subtree,
            persist_depth,
            follow,
        } => {
            cmd_sync(
                resolve_network(network, custom_heights.as_deref()),
                server,
                wallet_dir,
                ufvk,
                birthday,
                streams,
                chunk,
                sparse,
                chunk_split_bytes,
                memory_budget_bytes,
                write_behind,
                gpu_subtree,
                persist_depth,
                follow,
                anchor_retention,
                anchor_retention_interval,
            );
        }
        Cmd::Bench {
            network,
            server,
            alternate_server,
            ufvk,
            birthday,
            wallet_dir,
            graft,
            gpu_subtree,
            batch_combine,
            local_treestate,
            treestate_verify_sample,
            persist_depth,
            graft_verify_sample,
            json,
            keep,
        } => {
            cmd_bench(
                network.to_network(),
                server,
                alternate_server,
                ufvk,
                birthday,
                wallet_dir,
                graft,
                gpu_subtree,
                batch_combine,
                local_treestate,
                treestate_verify_sample,
                persist_depth,
                graft_verify_sample,
                json,
                keep,
            );
        }
        Cmd::Watch {
            network,
            server,
            wallet_dir,
            ufvk,
            birthday,
            interval_ms,
        } => {
            cmd_watch(
                network.to_network(),
                server,
                wallet_dir,
                ufvk,
                birthday,
                interval_ms,
            );
        }
        Cmd::Oracle {
            network,
            server,
            wallet_a,
            wallet_b,
            ufvk,
            birthday,
            sparse_b,
            write_behind_b,
            gpu_subtree_b,
            persist_depth_b,
            streams,
            chunk,
        } => {
            cmd_oracle(
                network.to_network(),
                server,
                wallet_a,
                wallet_b,
                ufvk,
                birthday,
                sparse_b,
                write_behind_b,
                gpu_subtree_b,
                persist_depth_b,
                streams,
                chunk,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_heights_parse_and_resolve_to_custom_params() {
        use zcash_protocol::consensus::{NetworkUpgrade, Parameters};

        // The valargroup Ironwood-testnet shape: main constants, genesis base,
        // the ironwood-era stand-in at 5000.
        let net = resolve_network(NetworkArg::Main, Some("genesis,nu6_2=5000"));
        assert_eq!(
            net.network_type(),
            zcash_protocol::consensus::NetworkType::Main
        );
        assert_eq!(
            net.activation_height(NetworkUpgrade::Sapling),
            Some(zcash_protocol::consensus::BlockHeight::from_u32(1))
        );
        assert_eq!(
            net.activation_height(NetworkUpgrade::Nu6_2),
            Some(zcash_protocol::consensus::BlockHeight::from_u32(5000))
        );

        assert!(parse_custom_heights("nu9=1").is_err());
        assert!(parse_custom_heights("sapling").is_err());
        assert!(parse_custom_heights("sapling=x").is_err());
    }

    #[test]
    fn parses_network_flag_and_defaults_to_main() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--network",
            "test",
            "--server",
            "https://lwd.example:443",
            "--wallet-dir",
            "/tmp/w",
        ])
        .expect("parses");
        assert!(matches!(
            cli.cmd,
            Cmd::Sync {
                network: NetworkArg::Test,
                ..
            }
        ));

        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "https://lwd.example:443",
            "--wallet-dir",
            "/tmp/w",
        ])
        .expect("parses");
        assert!(
            matches!(
                cli.cmd,
                Cmd::Sync {
                    network: NetworkArg::Main,
                    ..
                }
            ),
            "network must default to mainnet"
        );
    }

    #[test]
    fn derive_ufvk_produces_a_testnet_ufvk() {
        // The standard BIP-39 test mnemonic; testnet fixture derivation only.
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = bip39::Mnemonic::parse(phrase)
            .expect("valid mnemonic")
            .to_seed("");
        let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &zodl_slipstream::Network::TestNetwork,
            &seed,
            zip32::AccountId::ZERO,
        )
        .expect("derives");
        let encoded = usk
            .to_unified_full_viewing_key()
            .encode(&zodl_slipstream::Network::TestNetwork);
        assert!(
            encoded.starts_with("uviewtest1"),
            "testnet UFVK must carry the uviewtest HRP, got {encoded}"
        );
    }

    #[test]
    fn parses_bench_minimal() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "bench",
            "--server",
            "https://zec.rocks:443",
            "--ufvk",
            "uview1abc",
            "--birthday",
            "2500000",
        ])
        .expect("parses");
        // v0.4.0: graft + batch_combine default ON; bench mirrors production —
        // `--graft false --batch-combine false` is the baseline A/B form.
        assert!(matches!(
            cli.cmd,
            Cmd::Bench {
                graft: true,
                batch_combine: true,
                gpu_subtree: false,
                keep: false,
                ..
            }
        ));
    }

    #[test]
    fn parses_bench_full_flags() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "bench",
            "--server",
            "https://zec.rocks:443",
            "--ufvk",
            "uview1abc",
            "--birthday",
            "2500000",
            "--wallet-dir",
            "/tmp/benchw",
            "--graft",
            "true",
            "--gpu-subtree",
            "true",
            "--json",
            "/tmp/out.json",
            "--keep",
        ])
        .expect("parses");
        match cli.cmd {
            Cmd::Bench {
                graft,
                gpu_subtree,
                keep,
                json,
                wallet_dir,
                ..
            } => {
                assert!(graft && gpu_subtree && keep);
                assert_eq!(json.as_deref(), Some(std::path::Path::new("/tmp/out.json")));
                assert_eq!(
                    wallet_dir.as_deref(),
                    Some(std::path::Path::new("/tmp/benchw"))
                );
            }
            other => panic!("wrong cmd: {other:?}"),
        }
    }

    #[test]
    fn bench_requires_identity() {
        // A bench is always a fresh restore: ufvk + birthday are mandatory.
        assert!(Cli::try_parse_from(["slipstream", "bench", "--server", "http://x:1"]).is_err());
        assert!(
            Cli::try_parse_from([
                "slipstream",
                "bench",
                "--server",
                "http://x:1",
                "--ufvk",
                "uview1abc",
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_version_subcommand() {
        let cli = Cli::try_parse_from(["slipstream", "version"]).expect("parses");
        assert!(matches!(cli.cmd, Cmd::Version));
    }

    #[test]
    fn rejects_unknown_subcommand() {
        assert!(Cli::try_parse_from(["slipstream", "warp"]).is_err());
    }

    #[test]
    fn parse_server_happy_https() {
        let ep = parse_server("https://zec.rocks:443").expect("ok");
        assert_eq!(ep.host, "zec.rocks");
        assert_eq!(ep.port, 443);
        assert!(ep.tls);
    }

    #[test]
    fn parse_server_sad_missing_port() {
        let err = parse_server("https://zec.rocks").unwrap_err();
        assert!(err.contains("port"), "error should mention port: {err}");
    }

    #[test]
    fn parse_server_sad_bad_scheme() {
        let err = parse_server("ftp://zec.rocks:443").unwrap_err();
        assert!(err.contains("http"), "error should mention http: {err}");
    }

    #[test]
    fn parse_range_happy() {
        let (start, end) = parse_range("2500000..2600000").expect("ok");
        assert_eq!(start, 2_500_000);
        assert_eq!(end, 2_600_000);
    }

    #[test]
    fn parse_range_sad_end_before_start() {
        let err = parse_range("2600000..2500000").unwrap_err();
        assert!(err.contains(">="), "error should mention >=: {err}");
    }

    #[test]
    fn parse_range_rejects_inclusive_syntax() {
        let err = parse_range("2500000..=2600000").unwrap_err();
        assert!(err.contains("..="), "error should mention ..=: {err}");
    }

    #[test]
    fn parses_sync_subcommand() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
        ])
        .expect("parses");
        assert!(matches!(cli.cmd, Cmd::Sync { .. }));
    }

    #[test]
    fn sync_parses_sparse_flag() {
        // T6.6: default is now true; bare --sparse with ArgAction::Set still sets true.
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
        ])
        .expect("parses default");
        assert!(
            matches!(cli.cmd, Cmd::Sync { sparse: true, .. }),
            "default must be true"
        );
    }

    #[test]
    fn sync_sparse_false_is_overridable() {
        // T6.6: kill switch — `--sparse false` must produce sparse=false.
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
            "--sparse",
            "false",
        ])
        .expect("parses --sparse false");
        assert!(
            matches!(cli.cmd, Cmd::Sync { sparse: false, .. }),
            "--sparse false must override the default"
        );
    }

    #[test]
    fn sync_chunk_split_bytes_defaults_to_engine_default() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
        ])
        .expect("parses default");
        assert!(
            matches!(
                cli.cmd,
                Cmd::Sync {
                    chunk_split_bytes: zodl_slipstream::EngineConfig::DEFAULT_CHUNK_SPLIT_BYTES,
                    ..
                }
            ),
            "default chunk_split_bytes must equal EngineConfig::DEFAULT_CHUNK_SPLIT_BYTES"
        );
    }

    #[test]
    fn sync_chunk_split_bytes_is_overridable() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
            "--chunk-split-bytes",
            "2097152",
        ])
        .expect("parses --chunk-split-bytes");
        assert!(
            matches!(
                cli.cmd,
                Cmd::Sync {
                    chunk_split_bytes: 2_097_152,
                    ..
                }
            ),
            "--chunk-split-bytes must override the default"
        );
    }

    #[test]
    fn sync_memory_budget_defaults_to_engine_default() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
        ])
        .expect("parses default");
        assert!(
            matches!(
                cli.cmd,
                Cmd::Sync {
                    memory_budget_bytes: zodl_slipstream::EngineConfig::DEFAULT_MEMORY_BUDGET,
                    ..
                }
            ),
            "default memory_budget_bytes must equal EngineConfig::DEFAULT_MEMORY_BUDGET"
        );
    }

    #[test]
    fn sync_memory_budget_flag_parses() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
            "--memory-budget-bytes",
            "67108864",
        ])
        .expect("parses --memory-budget-bytes");
        assert!(
            matches!(
                cli.cmd,
                Cmd::Sync {
                    memory_budget_bytes: 67_108_864,
                    ..
                }
            ),
            "--memory-budget-bytes must override the default"
        );
    }

    #[test]
    fn sync_rejects_missing_server() {
        // --server is required for Sync
        let result =
            Cli::try_parse_from(["slipstream", "sync", "--wallet-dir", "/tmp/test-wallet"]);
        assert!(result.is_err(), "should fail without --server");
    }

    // A real mainnet UFVK (the repo's canonical darkside test key, copied here because
    // `wallet_session::TEST_UFVK` is `#[cfg(any(test, feature = "darkside"))]` and so not
    // reachable from this crate's tests). `validate_sync_args` now decodes, so the success
    // path needs a genuinely decodable key.
    const VALID_MAINNET_UFVK: &str = concat!(
        "uview17fme6ux853km45g9ep07djpfzeydxxgm22xpmr7arzxyutlusalgpqlx7suga4ahzywfuwz4jclm00u7g8u65qvvdt45kttnfunvschssg3h3g06txs9ja32vx3xa8dej3unnat",
        "gzjvd0vumk37t8es3ludldrtse3q6226ws7eq4q0ywz78nudwpepgdn7jmxz8yvp7k6gxkeynkam0f8aqf9qpeaej55zhkw39x7epayhndul0j4xjttdxxlnwcd09nr8svyx8j0zng0w6",
        "scx3m5unpkaqxcm3hslhlfg4caz7r8d4xy9wm7klkg79w7j0uyzec5s3yje20eg946r6rmkf532nfydu26s8q9ua7mwxw2j2ag7hfcuu652gw6uta03vlm05zju3a9rwc4h367kqzfqrc",
        "z35pdwdk2a7yqnk850un3ujxcvve45ueajgvtr6dj4ufszgqwdy0aedgmkalx2p7qed2suarwkr35dl0c8dnqp3"
    );

    #[test]
    fn sync_requires_birthday_with_ufvk() {
        // The (ufvk, no birthday) arm errors before any decode, so a placeholder key is fine.
        let net = zodl_slipstream::Network::MainNetwork;
        let result = validate_sync_args(&net, Some("uview1someufvk"), None);
        assert!(result.is_err(), "ufvk without birthday must error");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("birthday"),
            "error message should mention birthday: {msg}"
        );
    }

    #[test]
    fn sync_allows_no_ufvk_no_birthday() {
        let net = zodl_slipstream::Network::MainNetwork;
        let result = validate_sync_args(&net, None, None).expect("no args is valid");
        assert!(result.is_empty(), "no ufvk = no accounts to import");
    }

    #[test]
    fn sync_allows_ufvk_with_birthday() {
        let net = zodl_slipstream::Network::MainNetwork;
        let accounts = validate_sync_args(&net, Some(VALID_MAINNET_UFVK), Some(800_000))
            .expect("valid ufvk + birthday");
        assert_eq!(accounts.len(), 1, "one account to bootstrap");
        assert_eq!(
            u32::from(accounts[0].1),
            800_000,
            "birthday preserved as a BlockHeight"
        );
    }

    #[test]
    fn sync_rejects_undecodable_ufvk() {
        // Decoding now happens at the CLI boundary: a malformed --ufvk is a clean error.
        let net = zodl_slipstream::Network::MainNetwork;
        let result = validate_sync_args(&net, Some("uview1someufvk"), Some(800_000));
        assert!(result.is_err(), "an undecodable ufvk must error");
    }

    #[test]
    fn sync_allows_birthday_without_ufvk_returns_empty() {
        // birthday with no ufvk: silently ignored (no account to import).
        let net = zodl_slipstream::Network::MainNetwork;
        let result = validate_sync_args(&net, None, Some(800_000)).expect("birthday-only is valid");
        assert!(result.is_empty(), "expected no accounts, got {result:?}");
    }

    #[test]
    fn parses_oracle_subcommand() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "oracle",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-a",
            "/tmp/oa",
            "--wallet-b",
            "/tmp/ob",
            "--ufvk",
            "uview1someufvk",
            "--birthday",
            "1500000",
        ])
        .expect("parses");
        assert!(matches!(
            cli.cmd,
            Cmd::Oracle {
                write_behind_b: false,
                ..
            }
        ));
    }

    // ── T6.9 write-behind flags ────────────────────────────────────────────────

    #[test]
    fn sync_write_behind_defaults_on() {
        // T6.9 flip (2026-06-12): default ON; `--write-behind false` is the kill switch.
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
        ])
        .expect("parses without the flag");
        assert!(matches!(
            cli.cmd,
            Cmd::Sync {
                write_behind: true,
                ..
            }
        ));
    }

    #[test]
    fn sync_write_behind_bare_flag_enables() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
            "--write-behind",
        ])
        .expect("parses bare --write-behind");
        assert!(matches!(
            cli.cmd,
            Cmd::Sync {
                write_behind: true,
                ..
            }
        ));
    }

    #[test]
    fn sync_write_behind_explicit_false_accepted() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
            "--write-behind",
            "false",
        ])
        .expect("parses --write-behind false");
        assert!(matches!(
            cli.cmd,
            Cmd::Sync {
                write_behind: false,
                ..
            }
        ));
    }

    #[test]
    fn oracle_write_behind_b_parses() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "oracle",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-a",
            "/tmp/oa",
            "--wallet-b",
            "/tmp/ob",
            "--ufvk",
            "uview1someufvk",
            "--birthday",
            "1500000",
            "--sparse-b",
            "--write-behind-b",
        ])
        .expect("parses");
        assert!(matches!(
            cli.cmd,
            Cmd::Oracle {
                sparse_b: true,
                write_behind_b: true,
                ..
            }
        ));
    }

    #[test]
    fn gpu_subtree_flags_parse() {
        // oracle --gpu-subtree-b (B0.4 acceptance-gate flag)
        let cli = Cli::try_parse_from([
            "slipstream",
            "oracle",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-a",
            "/tmp/oa",
            "--wallet-b",
            "/tmp/ob",
            "--ufvk",
            "uview1someufvk",
            "--birthday",
            "1500000",
            "--sparse-b",
            "--gpu-subtree-b",
        ])
        .expect("parses");
        assert!(matches!(
            cli.cmd,
            Cmd::Oracle {
                gpu_subtree_b: true,
                ..
            }
        ));

        // sync --gpu-subtree
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/w",
            "--gpu-subtree",
        ])
        .expect("parses");
        assert!(matches!(
            cli.cmd,
            Cmd::Sync {
                gpu_subtree: true,
                ..
            }
        ));
    }

    #[test]
    fn persist_depth_flags_parse() {
        // oracle --persist-depth-b
        let cli = Cli::try_parse_from([
            "slipstream",
            "oracle",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-a",
            "/tmp/oa",
            "--wallet-b",
            "/tmp/ob",
            "--ufvk",
            "uview1someufvk",
            "--birthday",
            "1500000",
            "--sparse-b",
            "--persist-depth-b",
            "4",
        ])
        .expect("parses");
        assert!(matches!(
            cli.cmd,
            Cmd::Oracle {
                persist_depth_b: 4,
                ..
            }
        ));

        // sync --persist-depth
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/w",
            "--persist-depth",
            "3",
        ])
        .expect("parses");
        assert!(matches!(
            cli.cmd,
            Cmd::Sync {
                persist_depth: 3,
                ..
            }
        ));

        // default depth = 1
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/w",
        ])
        .expect("parses");
        assert!(
            matches!(
                cli.cmd,
                Cmd::Sync {
                    persist_depth: 1,
                    ..
                }
            ),
            "default depth must be 1"
        );
    }

    #[test]
    fn require_gpu_feature_noop_when_not_requested() {
        // Must not exit/panic when the flag isn't set, regardless of build features.
        require_gpu_feature_if(false, "--gpu-subtree-b");
        require_gpu_feature_if(false, "--gpu-subtree");
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn require_gpu_feature_ok_when_built_with_gpu() {
        // With the gpu feature on, requesting gpu is allowed (no exit/panic). The
        // exit branch (requested && !feature) can only be covered by a subprocess.
        require_gpu_feature_if(true, "--gpu-subtree-b");
    }

    // ── T8.1 follow flag ──────────────────────────────────────────────────────

    #[test]
    fn sync_follow_flag_parses() {
        // --follow defaults to false.
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
        ])
        .expect("parses without --follow");
        assert!(
            matches!(cli.cmd, Cmd::Sync { follow: false, .. }),
            "default must be false"
        );

        // --follow enables following.
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
            "--follow",
        ])
        .expect("parses --follow");
        assert!(
            matches!(cli.cmd, Cmd::Sync { follow: true, .. }),
            "--follow must enable following"
        );
    }
}
