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

//! Retained, request-driven OHTTP health evidence. This channel does not retry requests,
//! infer an outage, or change transport results. All times use `CLOCK_MONOTONIC`.
//!
//! Notifications are coalesced on an owned worker. Producers only update bounded state
//! and attempt a nonblocking wake; application callbacks never run on transport threads
//! or under channel locks. A snapshot is evidence, not a new request or a recovery verdict.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak, mpsc};
use std::thread::{self, JoinHandle};

/// Configuration identity only: never supply a per-request URL or payload here.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct HealthRoute {
    pub gateway_host: String,
    pub relay_url: String,
    pub via_tor: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthSource {
    Native,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthScope {
    Route,
    Lightwalletd,
    ExchangeRates,
    Swaps,
    Voting,
    Flexa,
    Other,
}

/// Only transport unavailability describes an unreachable private route. In particular,
/// a backend rejection and a rate-limit pause must not become relay-outage evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthOutcome {
    Usable,
    TransportUnavailable,
    BackendUnavailable,
    RateLimited { retry_not_before_nanoseconds: u64 },
    PolicyRejected,
    ConfigurationFailure,
    ResponseRejected,
    Cancelled,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthStage {
    Connection,
    KeyConfiguration,
    ResponseHead,
    ResponseBody,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthPurpose {
    Background,
    UserOperation,
    Diagnostic,
}

/// Local correlation only. The UUID bytes are never sent over the network.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HealthOperation {
    pub id: [u8; 16],
    pub started_at_nanoseconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthObservation {
    pub source: HealthSource,
    pub route: HealthRoute,
    pub scope: HealthScope,
    pub outcome: HealthOutcome,
    pub stage: HealthStage,
    /// Captured at request start. Zero is used for retained evidence with no subscriber.
    pub generation: u64,
    pub version: u64,
    pub request_id: u64,
    pub started_at_nanoseconds: u64,
    pub observed_at_nanoseconds: u64,
    pub operation: Option<HealthOperation>,
    pub purpose: HealthPurpose,
    /// Replayed from route history at subscription time. Never use this as fresh traffic.
    pub historical: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthSnapshot {
    pub generation: u64,
    pub version: u64,
    /// At most 126 entries: seven scopes × nine outcomes × two purpose classes.
    /// Success and failure coexist so a coalesced wake cannot erase their ordering.
    pub observations: Vec<HealthObservation>,
}

struct SubscriberState {
    closed: bool,
    snapshot: HealthSnapshot,
}

struct Subscriber {
    state: Mutex<SubscriberState>,
    wake: mpsc::SyncSender<()>,
}

struct RouteState {
    observations: Vec<HealthObservation>,
    subscribers: Vec<Weak<Subscriber>>,
}

struct RouteChannel {
    route: HealthRoute,
    state: Mutex<RouteState>,
}

#[derive(Default)]
struct Registry {
    routes: HashMap<HealthRoute, Weak<RouteChannel>>,
    // Only the most recent 32 routes stay alive without a live ticket/subscription.
    recent: VecDeque<Arc<RouteChannel>>,
}

impl Registry {
    fn route(&mut self, route: &HealthRoute) -> Arc<RouteChannel> {
        self.routes.retain(|_, channel| channel.strong_count() > 0);
        let channel = self
            .routes
            .get(route)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| {
                let channel = Arc::new(RouteChannel {
                    route: route.clone(),
                    state: Mutex::new(RouteState {
                        observations: Vec::new(),
                        subscribers: Vec::new(),
                    }),
                });
                self.routes.insert(route.clone(), Arc::downgrade(&channel));
                channel
            });
        self.recent.retain(|entry| !Arc::ptr_eq(entry, &channel));
        self.recent.push_back(channel.clone());
        if self.recent.len() > 32 {
            self.recent.pop_front();
        }
        channel
    }
}

fn channel(route: &HealthRoute) -> Arc<RouteChannel> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY
        .get_or_init(|| Mutex::new(Registry::default()))
        .lock()
        .unwrap()
        .route(route)
}

/// Nanoseconds in the same OS monotonic clock domain used by native health consumers.
pub fn monotonic_time_nanoseconds() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `time` is writable and CLOCK_MONOTONIC requires no other resources.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) };
    assert_eq!(result, 0, "CLOCK_MONOTONIC is required for health evidence");
    (time.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(time.tv_nsec as u64)
}

fn retain(observations: &mut Vec<HealthObservation>, observation: HealthObservation) {
    let existing = observations.iter_mut().find(|old| {
        old.scope == observation.scope
            && (old.purpose == HealthPurpose::Diagnostic)
                == (observation.purpose == HealthPurpose::Diagnostic)
            && std::mem::discriminant(&old.outcome) == std::mem::discriminant(&observation.outcome)
    });
    if let Some(old) = existing {
        let newer = if observation.purpose != HealthPurpose::Diagnostic
            && observation.scope == HealthScope::Route
            && observation.outcome == HealthOutcome::Usable
        {
            (
                observation.started_at_nanoseconds,
                observation.observed_at_nanoseconds,
                observation.version,
            ) > (
                old.started_at_nanoseconds,
                old.observed_at_nanoseconds,
                old.version,
            )
        } else {
            (observation.observed_at_nanoseconds, observation.version)
                > (old.observed_at_nanoseconds, old.version)
        };
        if newer {
            *old = observation;
        }
    } else {
        observations.push(observation);
    }
}

/// Owned subscription. Closing from another thread waits for an active callback to finish.
/// Closing inside its own callback retires the channel immediately; that callback is
/// already executing and may return normally, but no subsequent callback can start.
pub struct HealthSubscription {
    subscriber: Arc<Subscriber>,
    // Keeps a live route discoverable even after the bounded history cache evicts it.
    _route: Arc<RouteChannel>,
    worker: Option<JoinHandle<()>>,
}

impl HealthSubscription {
    pub fn snapshot(&self) -> HealthSnapshot {
        self.subscriber.state.lock().unwrap().snapshot.clone()
    }

    /// Idempotent callback fence. Never call while holding a lock needed by the callback.
    pub fn close(&mut self) {
        self.subscriber.state.lock().unwrap().closed = true;
        let _ = self.subscriber.wake.try_send(());
        if let Some(worker) = self.worker.take() {
            if worker.thread().id() != thread::current().id() {
                // A consumer panic must not turn teardown into a second panic.
                let _ = worker.join();
            }
        }
    }
}

impl Drop for HealthSubscription {
    fn drop(&mut self) {
        self.close();
    }
}

pub fn subscribe(
    route: HealthRoute,
    generation: u64,
    notify: Arc<dyn Fn(HealthSnapshot) + Send + Sync>,
) -> HealthSubscription {
    let route = channel(&route);
    let (wake, receiver) = mpsc::sync_channel(1);
    let subscriber;
    {
        let mut state = route.state.lock().unwrap();
        let observations: Vec<_> = state
            .observations
            .iter()
            .cloned()
            .map(|mut observation| {
                observation.historical = true;
                observation
            })
            .collect();
        let version = observations
            .iter()
            .map(|observation| observation.version)
            .max()
            .unwrap_or(0);
        subscriber = Arc::new(Subscriber {
            state: Mutex::new(SubscriberState {
                closed: false,
                snapshot: HealthSnapshot {
                    generation,
                    version,
                    observations,
                },
            }),
            wake,
        });
        state
            .subscribers
            .retain(|subscriber| subscriber.strong_count() > 0);
        state.subscribers.push(Arc::downgrade(&subscriber));
        if version > 0 {
            let _ = subscriber.wake.try_send(());
        }
    }
    let shared = subscriber.clone();
    let worker = thread::Builder::new()
        .name("ohttp-health".into())
        .spawn(move || {
            while receiver.recv().is_ok() {
                let snapshot = {
                    let state = shared.state.lock().unwrap();
                    if state.closed {
                        break;
                    }
                    state.snapshot.clone()
                };
                // No registry, transport, wallet, or subscriber lock is held here.
                notify(snapshot);
            }
        })
        .expect("could not start OHTTP health notification worker");
    HealthSubscription {
        subscriber,
        _route: route,
        worker: Some(worker),
    }
}

/// A logical request ticket: its start identity and recipients never change on completion.
pub struct HealthRequest {
    route: Arc<RouteChannel>,
    recipients: Vec<(Weak<Subscriber>, u64)>,
    request_id: u64,
    started_at_nanoseconds: u64,
    scope: HealthScope,
    purpose: HealthPurpose,
    operation: Option<HealthOperation>,
}

pub fn begin_request(route: &HealthRoute, scope: HealthScope) -> HealthRequest {
    static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);
    let started_at_nanoseconds = monotonic_time_nanoseconds();
    let route = channel(route);
    let recipients = {
        let mut state = route.state.lock().unwrap();
        state
            .subscribers
            .retain(|subscriber| subscriber.strong_count() > 0);
        state
            .subscribers
            .iter()
            .filter_map(|subscriber| {
                let shared = subscriber.upgrade()?;
                let state = shared.state.lock().unwrap();
                (!state.closed).then(|| (subscriber.clone(), state.snapshot.generation))
            })
            .collect()
    };
    HealthRequest {
        route,
        recipients,
        request_id: NEXT_REQUEST.fetch_add(1, Ordering::Relaxed),
        started_at_nanoseconds,
        scope,
        purpose: HealthPurpose::Background,
        operation: None,
    }
}

impl HealthRequest {
    pub fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Attach an explicit local context before dispatching the request.
    pub fn with_context(
        mut self,
        purpose: HealthPurpose,
        operation: Option<HealthOperation>,
    ) -> Self {
        self.purpose = purpose;
        self.operation = operation;
        self
    }

    /// An authenticated inner response proves the route worked, independently of its
    /// backend result. Preserve this logical request's start and local identity.
    pub fn record_route_usable(&self, stage: HealthStage) {
        self.record_scope(HealthScope::Route, HealthOutcome::Usable, stage);
    }

    pub fn record(&self, outcome: HealthOutcome, stage: HealthStage) {
        self.record_scope(self.scope, outcome, stage);
    }

    fn record_scope(&self, scope: HealthScope, outcome: HealthOutcome, stage: HealthStage) {
        static NEXT_VERSION: AtomicU64 = AtomicU64::new(1);
        // Capture evidence time on the producer, never on the notification worker.
        let observed_at_nanoseconds = monotonic_time_nanoseconds();
        let mut state = self.route.state.lock().unwrap();
        let version = NEXT_VERSION.fetch_add(1, Ordering::Relaxed);
        let observation = HealthObservation {
            source: HealthSource::Native,
            route: self.route.route.clone(),
            scope,
            outcome,
            stage,
            generation: self
                .recipients
                .first()
                .map_or(0, |(_, generation)| *generation),
            version,
            request_id: self.request_id,
            started_at_nanoseconds: self.started_at_nanoseconds,
            observed_at_nanoseconds,
            purpose: self.purpose,
            operation: self.operation,
            historical: false,
        };
        retain(&mut state.observations, observation.clone());
        for (recipient, generation) in &self.recipients {
            if let Some(recipient) = recipient.upgrade() {
                let mut state = recipient.state.lock().unwrap();
                if state.closed {
                    continue;
                }
                let mut observation = observation.clone();
                observation.generation = *generation;
                state.snapshot.version = version;
                retain(&mut state.snapshot.observations, observation);
                // A full channel already promises a fresh snapshot on the worker's next turn.
                let _ = recipient.wake.try_send(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier, mpsc};
    use std::thread;
    use std::time::Duration;

    fn route() -> HealthRoute {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        HealthRoute {
            gateway_host: format!(
                "gateway-{}.test",
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ),
            relay_url: "https://relay.test/".into(),
            via_tor: false,
        }
    }

    fn quiet(route: &HealthRoute, generation: u64) -> HealthSubscription {
        subscribe(route.clone(), generation, Arc::new(|_| {}))
    }

    #[test]
    fn ordinary_route_recovery_survives_late_older_completion() {
        let route = route();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (snap_tx, snap_rx) = mpsc::channel();
        let release = Arc::new(Barrier::new(2));
        let callback_release = release.clone();
        let first = std::sync::atomic::AtomicBool::new(true);
        let subscription = subscribe(
            route.clone(),
            7,
            Arc::new(move |snapshot| {
                if first.swap(false, Ordering::Relaxed) {
                    entered_tx.send(()).unwrap();
                    callback_release.wait();
                }
                snap_tx.send(snapshot).unwrap();
            }),
        );
        begin_request(&route, HealthScope::Lightwalletd)
            .record(HealthOutcome::TransportUnavailable, HealthStage::Connection);
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut old = begin_request(&route, HealthScope::Lightwalletd);
        old.started_at_nanoseconds = 10;
        let mut fresh = begin_request(&route, HealthScope::Lightwalletd).with_context(
            HealthPurpose::UserOperation,
            Some(HealthOperation {
                id: [9; 16],
                started_at_nanoseconds: 20,
            }),
        );
        fresh.started_at_nanoseconds = 30;
        fresh.record_route_usable(HealthStage::ResponseHead);
        let expected = subscription
            .snapshot()
            .observations
            .into_iter()
            .find(|o| o.scope == HealthScope::Route && o.outcome == HealthOutcome::Usable)
            .unwrap();
        old.record_route_usable(HealthStage::Complete);
        let version = subscription.snapshot().version;
        // Release before assertions so a RED cannot strand the real callback worker.
        release.wait();
        let delivered = loop {
            let snapshot = snap_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            if snapshot.version == version {
                break snapshot;
            }
        };
        let success = delivered
            .observations
            .iter()
            .find(|o| o.scope == HealthScope::Route)
            .unwrap();
        assert_eq!(
            success, &expected,
            "late older completion erased fresh ordinary recovery"
        );
        let mut historical = expected;
        historical.historical = true;
        let replay = quiet(&route, 8).snapshot();
        assert_eq!(
            replay
                .observations
                .iter()
                .find(|o| o.scope == HealthScope::Route),
            Some(&historical)
        );
    }

    #[test]
    fn diagnostic_retention_cannot_replace_ordinary_evidence() {
        let route = route();
        let subscription = quiet(&route, 7);
        let ordinary = begin_request(&route, HealthScope::Lightwalletd);
        ordinary.record_route_usable(HealthStage::ResponseHead);
        ordinary.record(HealthOutcome::TransportUnavailable, HealthStage::Connection);
        let expected = subscription.snapshot().observations;
        let diagnostic = begin_request(&route, HealthScope::Lightwalletd)
            .with_context(HealthPurpose::Diagnostic, None);
        diagnostic.record_route_usable(HealthStage::ResponseHead);
        diagnostic.record(
            HealthOutcome::TransportUnavailable,
            HealthStage::ResponseBody,
        );
        let snapshot = subscription.snapshot();
        assert_eq!(
            snapshot.observations.len(),
            4,
            "diagnostics must have separate finite buckets"
        );
        for observation in expected {
            assert!(snapshot.observations.contains(&observation));
        }
        let mut old_failure = begin_request(&route, HealthScope::Lightwalletd);
        old_failure.started_at_nanoseconds = 1;
        old_failure.record(HealthOutcome::TransportUnavailable, HealthStage::Complete);
        assert!(
            subscription
                .snapshot()
                .observations
                .iter()
                .any(|o| o.purpose != HealthPurpose::Diagnostic
                    && o.scope == HealthScope::Lightwalletd
                    && o.request_id == old_failure.request_id())
        );
        for scope in [
            HealthScope::Route,
            HealthScope::Lightwalletd,
            HealthScope::ExchangeRates,
            HealthScope::Swaps,
            HealthScope::Voting,
            HealthScope::Flexa,
            HealthScope::Other,
        ] {
            for outcome in [
                HealthOutcome::Usable,
                HealthOutcome::TransportUnavailable,
                HealthOutcome::BackendUnavailable,
                HealthOutcome::RateLimited {
                    retry_not_before_nanoseconds: 900,
                },
                HealthOutcome::PolicyRejected,
                HealthOutcome::ConfigurationFailure,
                HealthOutcome::ResponseRejected,
                HealthOutcome::Cancelled,
                HealthOutcome::Inconclusive,
            ] {
                for purpose in [
                    HealthPurpose::Background,
                    HealthPurpose::UserOperation,
                    HealthPurpose::Diagnostic,
                ] {
                    for _ in 0..100 {
                        begin_request(&route, scope)
                            .with_context(purpose, None)
                            .record(outcome, HealthStage::Complete);
                    }
                }
            }
        }
        assert_eq!(subscription.snapshot().observations.len(), 126);
    }

    #[test]
    fn route_success_preserves_the_logical_service_request_identity() {
        let route = route();
        let subscription = quiet(&route, 7);
        let request = begin_request(&route, HealthScope::Lightwalletd);
        request.record_route_usable(HealthStage::ResponseHead);
        request.record(HealthOutcome::BackendUnavailable, HealthStage::Complete);
        let observations = subscription.snapshot().observations;
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].scope, HealthScope::Route);
        assert_eq!(observations[0].outcome, HealthOutcome::Usable);
        assert_eq!(observations[0].request_id, observations[1].request_id);
        assert_eq!(
            observations[0].started_at_nanoseconds,
            observations[1].started_at_nanoseconds
        );
    }

    // Losing retained evidence or replacing its timestamps would manufacture fresh traffic.
    #[test]
    fn snapshot_replay_preserves_original_live_evidence() {
        let route = route();
        let subscription = quiet(&route, 7);
        let request = begin_request(&route, HealthScope::Lightwalletd);
        request.record(HealthOutcome::TransportUnavailable, HealthStage::Connection);
        let first = subscription.snapshot();
        let replay = subscription.snapshot();
        assert!(!replay.observations[0].historical);
        assert_eq!(first, replay);
        assert_eq!(replay.generation, 7);
        assert_eq!(replay.observations.len(), 1);
        let observation = &replay.observations[0];
        assert!(observation.started_at_nanoseconds <= observation.observed_at_nanoseconds);
        assert_eq!(observation.generation, 7);
        assert_eq!(observation.purpose, HealthPurpose::Background);
        assert_eq!(observation.operation, None);
    }

    // Coalescing must keep both sides of availability and non-availability categories.
    #[test]
    fn retention_is_bounded_without_erasing_success_failure_or_rate_limit() {
        let route = route();
        let subscription = quiet(&route, 1);
        let failed = begin_request(&route, HealthScope::Lightwalletd);
        failed.record(
            HealthOutcome::TransportUnavailable,
            HealthStage::ResponseBody,
        );
        let failure_id = subscription.snapshot().observations[0].request_id;
        for _ in 0..1000 {
            begin_request(&route, HealthScope::Lightwalletd)
                .record(HealthOutcome::Usable, HealthStage::Complete);
        }
        begin_request(&route, HealthScope::Lightwalletd).record(
            HealthOutcome::RateLimited {
                retry_not_before_nanoseconds: 500,
            },
            HealthStage::ResponseHead,
        );
        let snapshot = subscription.snapshot();
        assert_eq!(snapshot.observations.len(), 3);
        assert!(
            snapshot
                .observations
                .iter()
                .any(|o| o.request_id == failure_id)
        );
        assert!(
            snapshot
                .observations
                .iter()
                .any(|o| o.outcome == HealthOutcome::Usable)
        );
        assert!(
            snapshot
                .observations
                .iter()
                .any(|o| matches!(o.outcome, HealthOutcome::RateLimited { .. }))
        );
    }

    // Late consumers recover completed evidence without treating it as newly started traffic.
    #[test]
    fn late_subscription_replays_bounded_history_without_refreshing_it() {
        let route = route();
        let request = begin_request(&route, HealthScope::Lightwalletd);
        request.record(HealthOutcome::TransportUnavailable, HealthStage::Connection);
        let first = quiet(&route, 1);
        let original = first.snapshot().observations[0].clone();
        assert!(original.historical);
        drop(first);
        let (tx, rx) = mpsc::channel();
        let second = subscribe(
            route,
            2,
            Arc::new(move |snapshot| {
                tx.send(snapshot).unwrap();
            }),
        );
        let replay = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(replay.generation, 2);
        assert_eq!(replay.observations[0], original);
        assert_eq!(second.snapshot().observations[0], original);
    }

    #[test]
    fn explicit_context_survives_multiple_stages_of_one_request() {
        let route = route();
        let subscription = quiet(&route, 1);
        let operation = HealthOperation {
            id: [42; 16],
            started_at_nanoseconds: 123,
        };
        let request = begin_request(&route, HealthScope::Voting)
            .with_context(HealthPurpose::UserOperation, Some(operation));
        request.record(HealthOutcome::Usable, HealthStage::ResponseHead);
        request.record(
            HealthOutcome::TransportUnavailable,
            HealthStage::ResponseBody,
        );
        let snapshot = subscription.snapshot();
        assert_eq!(snapshot.observations.len(), 2);
        for observation in &snapshot.observations {
            assert_eq!(observation.operation, Some(operation));
            assert_eq!(observation.purpose, HealthPurpose::UserOperation);
            assert_eq!(observation.request_id, request.request_id());
            assert_eq!(
                observation.started_at_nanoseconds,
                snapshot.observations[0].started_at_nanoseconds
            );
        }
        begin_request(&route, HealthScope::Route)
            .with_context(HealthPurpose::Diagnostic, None)
            .record(HealthOutcome::Inconclusive, HealthStage::Complete);
        let snapshot = subscription.snapshot();
        let diagnostic = snapshot
            .observations
            .iter()
            .find(|o| o.scope == HealthScope::Route)
            .unwrap();
        assert_eq!(diagnostic.purpose, HealthPurpose::Diagnostic);
        assert_eq!(diagnostic.operation, None);
    }

    #[test]
    fn inactive_route_history_is_evicted_but_active_subscriptions_stay_discoverable() {
        let inactive_route = route();
        begin_request(&inactive_route, HealthScope::Route)
            .record(HealthOutcome::Usable, HealthStage::Complete);
        let active_route = route();
        let active = quiet(&active_route, 1);
        for _ in 0..128 {
            begin_request(&route(), HealthScope::Route)
                .record(HealthOutcome::Usable, HealthStage::Complete);
        }
        assert!(quiet(&inactive_route, 2).snapshot().observations.is_empty());
        begin_request(&active_route, HealthScope::Route)
            .record(HealthOutcome::TransportUnavailable, HealthStage::Connection);
        assert_eq!(active.snapshot().observations.len(), 1);
    }

    #[test]
    fn callback_can_drop_its_own_subscription_without_deadlocking() {
        let route = route();
        let slot = Arc::new(std::sync::Mutex::new(None::<HealthSubscription>));
        let owned_slot = slot.clone();
        let (tx, rx) = mpsc::channel();
        let subscription = subscribe(
            route.clone(),
            1,
            Arc::new(move |_| {
                drop(owned_slot.lock().unwrap().take());
                tx.send(()).unwrap();
            }),
        );
        *slot.lock().unwrap() = Some(subscription);
        let request = begin_request(&route, HealthScope::Route);
        request.record(HealthOutcome::Usable, HealthStage::Complete);
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        request.record(HealthOutcome::TransportUnavailable, HealthStage::Connection);
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(5)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
        assert!(slot.lock().unwrap().is_none());
    }

    // A ticket must never discover a replacement session when it finishes.
    #[test]
    fn request_finishing_after_close_cannot_enter_new_generation() {
        let route = route();
        let mut old = quiet(&route, 1);
        let request = begin_request(&route, HealthScope::Lightwalletd);
        let old_request_id = request.request_id();
        old.close();
        let new_subscription = quiet(&route, 2);
        request.record(
            HealthOutcome::TransportUnavailable,
            HealthStage::ResponseBody,
        );
        assert_eq!(new_subscription.snapshot().generation, 2);
        assert!(
            !new_subscription
                .snapshot()
                .observations
                .iter()
                .any(|o| o.request_id == old_request_id)
        );
        begin_request(&route, HealthScope::Lightwalletd)
            .record(HealthOutcome::Usable, HealthStage::Complete);
        assert_eq!(new_subscription.snapshot().observations.len(), 1);
        assert!(old.snapshot().observations.is_empty());
    }

    #[test]
    fn request_started_before_subscribing_does_not_become_new_traffic() {
        let route = route();
        let request = begin_request(&route, HealthScope::Lightwalletd);
        let subscription = quiet(&route, 1);
        request.record(HealthOutcome::TransportUnavailable, HealthStage::Connection);
        assert!(subscription.snapshot().observations.is_empty());
    }

    // Late completion must retain its old start, not masquerade as recovery.
    #[test]
    fn overlapping_success_preserves_start_and_evidence_order() {
        let route = route();
        let subscription = quiet(&route, 1);
        let old = begin_request(&route, HealthScope::Lightwalletd);
        begin_request(&route, HealthScope::Lightwalletd)
            .record(HealthOutcome::TransportUnavailable, HealthStage::Connection);
        old.record(HealthOutcome::Usable, HealthStage::Complete);
        let snapshot = subscription.snapshot();
        let failure = snapshot
            .observations
            .iter()
            .find(|o| o.outcome == HealthOutcome::TransportUnavailable)
            .unwrap();
        let success = snapshot
            .observations
            .iter()
            .find(|o| o.outcome == HealthOutcome::Usable)
            .unwrap();
        assert!(success.started_at_nanoseconds <= failure.observed_at_nanoseconds);
        assert!(success.observed_at_nanoseconds >= failure.observed_at_nanoseconds);
        assert!(success.version > failure.version);
    }

    #[test]
    fn concurrent_writers_keep_unique_versions_and_all_scopes() {
        let route = route();
        let subscription = quiet(&route, 1);
        thread::scope(|threads| {
            for scope in [
                HealthScope::Route,
                HealthScope::Lightwalletd,
                HealthScope::ExchangeRates,
                HealthScope::Swaps,
                HealthScope::Voting,
                HealthScope::Flexa,
                HealthScope::Other,
            ] {
                let route = &route;
                threads.spawn(move || {
                    for _ in 0..100 {
                        begin_request(route, scope)
                            .record(HealthOutcome::TransportUnavailable, HealthStage::Connection);
                        begin_request(route, scope)
                            .record(HealthOutcome::Usable, HealthStage::Complete);
                    }
                });
            }
        });
        let snapshot = subscription.snapshot();
        assert_eq!(snapshot.observations.len(), 14);
        let mut versions: Vec<_> = snapshot.observations.iter().map(|o| o.version).collect();
        versions.sort();
        versions.dedup();
        assert_eq!(versions.len(), 14);
        assert_eq!(versions.last(), Some(&snapshot.version));
    }

    // A blocked consumer must not block writers, and a full wake queue cannot lose the final facts.
    #[test]
    fn stalled_callback_coalesces_wakeups_without_blocking_writers() {
        let route = route();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (snap_tx, snap_rx) = mpsc::channel();
        let release = Arc::new(Barrier::new(2));
        let callback_release = release.clone();
        let first = std::sync::atomic::AtomicBool::new(true);
        let subscription = subscribe(
            route.clone(),
            1,
            Arc::new(move |snapshot| {
                if first.swap(false, std::sync::atomic::Ordering::Relaxed) {
                    entered_tx.send(()).unwrap();
                    callback_release.wait();
                }
                snap_tx.send(snapshot).unwrap();
            }),
        );
        begin_request(&route, HealthScope::Lightwalletd)
            .record(HealthOutcome::TransportUnavailable, HealthStage::Connection);
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let (written_tx, written_rx) = mpsc::channel();
        let writer_route = route.clone();
        let writer = thread::spawn(move || {
            for _ in 0..1000 {
                begin_request(&writer_route, HealthScope::Lightwalletd)
                    .record(HealthOutcome::Usable, HealthStage::Complete);
            }
            written_tx.send(()).unwrap();
        });
        let result = written_rx.recv_timeout(Duration::from_secs(5));
        release.wait();
        result.unwrap();
        writer.join().unwrap();
        let expected = subscription.snapshot().version;
        loop {
            let snapshot = snap_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            if snapshot.version == expected {
                assert_eq!(snapshot.observations.len(), 2);
                break;
            }
        }
    }

    // Closing waits for the in-flight callback and prevents any queued callback starting later.
    #[test]
    fn close_fences_active_and_queued_callbacks_and_is_idempotent() {
        let route = route();
        let (entered_tx, entered_rx) = mpsc::channel();
        let release = Arc::new(Barrier::new(2));
        let callback_release = release.clone();
        let callbacks = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let count = callbacks.clone();
        let mut subscription = subscribe(
            route.clone(),
            1,
            Arc::new(move |_| {
                count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                entered_tx.send(()).unwrap();
                callback_release.wait();
            }),
        );
        let request = begin_request(&route, HealthScope::Lightwalletd);
        request.record(HealthOutcome::Usable, HealthStage::ResponseHead);
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        request.record(
            HealthOutcome::TransportUnavailable,
            HealthStage::ResponseBody,
        );
        let shared = subscription.subscriber.clone();
        let (closing_tx, closing_rx) = mpsc::channel();
        let (closed_tx, closed_rx) = mpsc::channel();
        let closer = thread::spawn(move || {
            closing_tx.send(()).unwrap();
            subscription.close();
            subscription.close();
            closed_tx.send(()).unwrap();
        });
        closing_rx.recv().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !shared.state.lock().unwrap().closed {
            assert!(std::time::Instant::now() < deadline);
            thread::yield_now();
        }
        assert!(closed_rx.try_recv().is_err());
        release.wait();
        closed_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        closer.join().unwrap();
        let before = callbacks.load(std::sync::atomic::Ordering::Relaxed);
        request.record(HealthOutcome::Usable, HealthStage::Complete);
        let callbacks_after_close = callbacks.load(std::sync::atomic::Ordering::Relaxed) - before;
        assert_eq!(callbacks_after_close, 0);
        assert_eq!(before, 1);
    }

    #[test]
    fn route_and_subscription_ownership_are_independent() {
        let route = route();
        let mut tor = route.clone();
        tor.via_tor = true;
        let first = quiet(&route, 1);
        let second = quiet(&route, 2);
        let tor_subscription = quiet(&tor, 3);
        begin_request(&route, HealthScope::Swaps)
            .record(HealthOutcome::BackendUnavailable, HealthStage::Complete);
        assert_eq!(first.snapshot().observations[0].generation, 1);
        assert_eq!(second.snapshot().observations[0].generation, 2);
        assert!(tor_subscription.snapshot().observations.is_empty());
        drop(first);
        begin_request(&route, HealthScope::Swaps)
            .record(HealthOutcome::Usable, HealthStage::Complete);
        assert_eq!(second.snapshot().observations.len(), 2);
    }
}
