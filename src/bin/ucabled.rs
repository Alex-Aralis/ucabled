// SPDX-License-Identifier: GPL-3.0-or-later

use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use ucabled::agent::CancelRequest;
use ucabled::ctap::{
    CMD_GET_NEXT_ASSERTION, CMD_MAKE_CREDENTIAL, CTAP1_ERR_CHANNEL_BUSY, CTAP1_ERR_TIMEOUT,
    CTAP2_ERR_INVALID_OPTION, CTAP2_ERR_NO_CREDENTIALS, CTAP2_ERR_NOT_ALLOWED,
    CTAP2_ERR_PIN_NOT_SET,
};
use ucabled::ctaphid::{CtapAction, Transport};
use ucabled::qr::RequestType;
use ucabled::uhid_dev::{FIDO_REPORT_DESCRIPTOR, UhidDevice, UhidEvent};
use ucabled::ui::Notifier;

const KEEPALIVE_INTERVAL: Duration = Duration::from_millis(150);

/// Delay before retrying a transient uhid read error.
const UHID_READ_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Log every Nth consecutive write failure (the first is always logged).
const WRITE_FAILURE_LOG_EVERY: u32 = 100;

/// Bytes of an input report needed to log its CID and command (cid + cmd).
const HID_REPORT_LOG_PREFIX: usize = 5;

/// Consecutive uhid read failures tolerated before giving up (and letting
/// systemd restart the service and recreate the device).
const MAX_UHID_READ_FAILURES: u32 = 10;

/// How long to wait for the user to answer the device-selection prompt before
/// declining. The helper has its own, slightly shorter, timeout.
const SELECT_TIMEOUT: Duration = Duration::from_secs(70);

/// User-facing notice when a tunnel redirect is refused.  Static text only:
/// nothing the tunnel server sent may cross into the user's session, where
/// the notification service may render markup.
const REDIRECT_REFUSED_SUMMARY: &str = "Passkey sign-in stopped";
const REDIRECT_REFUSED_BODY: &str = "The phone tunnel server sent an unexpected \
redirect, so the transaction was refused.  If this repeats, please report it; \
details are in the system journal (journalctl -u ucabled).";

/// Bound on queued UI cancellations.  Cancellations are only acted on when
/// they match the in-flight transaction, so a full queue can only ever mean
/// a misbehaving agent; excess ones are dropped in the D-Bus layer.
const CANCEL_QUEUE_SIZE: usize = 16;

/// Bound on queued device-selection answers, same rationale as
/// [`CANCEL_QUEUE_SIZE`].
const SELECT_QUEUE_SIZE: usize = 16;

/// An in-flight operation that the daemon is waiting on.
enum Pending {
    /// A caBLE transaction is running for `cid`; `abort` cancels it.
    /// `agent` is the registration generation of the agent the QR window
    /// was requested from, used to recognise stale agent-gone signals.
    Relay {
        cid: u32,
        abort: AbortHandle,
        agent: Option<u64>,
    },
    /// The user is being asked to choose the phone over another
    /// authenticator (e.g. a physical security key). Firefox's own prompt can
    /// only be answered by touching a physical key, so we ask through the
    /// agent.
    Select {
        cid: u32,
        deadline: tokio::time::Instant,
        agent: Option<u64>,
    },
}

impl Pending {
    fn cid(&self) -> u32 {
        match self {
            Pending::Relay { cid, .. } | Pending::Select { cid, .. } => *cid,
        }
    }

    fn agent(&self) -> Option<u64> {
        match self {
            Pending::Relay { agent, .. } | Pending::Select { agent, .. } => *agent,
        }
    }
}

/// Whether a cancel request applies to the pending operation.  A user
/// cancellation is tagged with the transaction id the agent was prompted
/// for, and an agent-gone signal with the agent's registration generation,
/// so a stale signal (a window closed after its transaction ended, an agent
/// whose successor already started a new transaction) cannot abort a later,
/// unrelated transaction.
fn cancel_aborts(request: &CancelRequest, pending: Option<&Pending>) -> bool {
    match (request, pending) {
        (CancelRequest::Transaction(tid), Some(p)) => p.cid() as u64 == *tid,
        (CancelRequest::AgentGone(generation), Some(p)) => p.agent() == Some(*generation),
        _ => false,
    }
}

fn main() -> Result<()> {
    let mut no_ui = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--no-ui" => no_ui = true,
            "-h" | "--help" => {
                println!(
                    "ucabled {} — virtual FIDO2 device relaying WebAuthn ceremonies\n\
                     to a phone via caBLE v2 (hybrid transport)\n\
                     \n\
                     Usage: ucabled [--no-ui]\n\
                     \n\
                     Options:\n\
                     \x20 --no-ui        print the QR code on the terminal instead of\n\
                     \x20                 using the UI agent\n\
                     \x20 -h, --help     print this help\n\
                     \x20 -V, --version  print the version",
                    env!("CARGO_PKG_VERSION")
                );
                return Ok(());
            }
            "-V" | "--version" => {
                println!("ucabled {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            other => {
                eprintln!("unknown argument: {other} (try --help)");
                std::process::exit(2);
            }
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let (cancel_tx, cancel_rx) = mpsc::channel::<CancelRequest>(CANCEL_QUEUE_SIZE);
    let (select_tx, select_rx) = mpsc::channel::<(u64, bool)>(SELECT_QUEUE_SIZE);
    let rt = tokio::runtime::Runtime::new()?;
    let notifier = if no_ui {
        Notifier::Terminal
    } else {
        match ucabled::agent::start(rt.handle(), cancel_tx.clone(), select_tx.clone()) {
            Ok(ui) => Notifier::Agent(ui),
            Err(e) => {
                tracing::warn!("UI bridge unavailable ({e:#}), falling back to terminal QR");
                Notifier::Terminal
            }
        }
    };

    rt.block_on(daemon_loop(notifier, cancel_rx, select_rx))
}

/// Build the keepalive timer.  The missed-tick policy is `Delay`, not the
/// default `Burst`: a keepalive's job is a steady cadence, and bursting the
/// backlog of an idle interval would flood the host with thousands of
/// reports the moment a transaction starts.
fn keepalive_interval() -> tokio::time::Interval {
    let mut interval = tokio::time::interval(KEEPALIVE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval
}

async fn daemon_loop(
    notifier: Notifier,
    mut cancel_rx: mpsc::Receiver<CancelRequest>,
    mut select_rx: mpsc::Receiver<(u64, bool)>,
) -> Result<()> {
    // Warn (do not fix) when /dev/uhid is writable by anyone but the ucabled
    // account: a loose node lets a local process create arbitrary virtual HID
    // devices.  We deliberately do not tighten permissions ourselves.
    if let Some(reason) = ucabled::uhid_perm::loose_reason(std::path::Path::new("/dev/uhid")) {
        tracing::warn!(
            "/dev/uhid is writable by more than the ucabled account ({reason}); a local \
             process could create arbitrary virtual HID devices (e.g. a keyboard). A stale \
             `uaccess` udev tag makes logind re-grant the active seat user; rebooting, or \
             `udevadm trigger /sys/class/misc/uhid`, with the current rule removes it."
        );
    }

    let device = UhidDevice::create("Phone Passkey Bridge", &FIDO_REPORT_DESCRIPTOR)
        .context("failed to create uhid device (is /dev/uhid accessible?)")?;
    tracing::info!("virtual FIDO2 device registered as 'Phone Passkey Bridge'");
    // Persistent caBLE identity (like Chromium's per-device identity), used as
    // the public key in every QR code and, once linking lands, as the desktop's
    // long-term identity towards linked phones.
    let identity = ucabled::identity::load_or_create(&ucabled::identity::state_dir())
        .context("failed to load the persistent identity key")?;
    let mut transport = Transport::new(ucabled::ctap::AAGUID);

    // systemd readiness, plus a keepalive when the unit sets WatchdogSec=: a
    // hung daemon is then restarted instead of silently wedging the HID
    // channel.
    ucabled::notify::ready();
    if let Some(interval) = ucabled::notify::watchdog_interval() {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                ucabled::notify::watchdog();
            }
        });
    }
    let (result_tx, mut result_rx) =
        mpsc::unbounded_channel::<(u32, Result<Vec<u8>, ucabled::error::TransactionError>)>();
    let mut pending: Option<Pending> = None;
    // Credentials still to serve via `authenticatorGetNextAssertion` after a
    // faked preflight response that reported more than one credential. Kept as
    // (rpId, remaining credential ids).
    let mut fake_assertions: Option<(String, std::collections::VecDeque<Vec<u8>>)> = None;
    let mut keepalive = keepalive_interval();
    let mut read_failures = 0u32;
    let mut write_failures = 0u32;
    // Number of processes holding the hidraw node open (several clients may
    // share it); the transport is reset when the last one closes.
    let mut open_count = 0u32;

    loop {
        tokio::select! {
            event = device.next_event() => {
                let event = match event {
                    Ok(e) => {
                        read_failures = 0;
                        e
                    }
                    Err(e) => {
                        // Transient errors (EINTR, a closed hidraw fd, ...)
                        // should not tear down the whole daemon, but a
                        // persistent one means the device is gone.
                        read_failures += 1;
                        if read_failures >= MAX_UHID_READ_FAILURES {
                            tracing::error!("uhid read failing repeatedly, giving up: {e}");
                            return Err(e.into());
                        }
                        tracing::warn!("uhid read error ({read_failures}/{MAX_UHID_READ_FAILURES}): {e}");
                        tokio::time::sleep(UHID_READ_RETRY_DELAY).await;
                        continue;
                    }
                };
                match event {
                    UhidEvent::Output(report) => {
                        if report.len() >= HID_REPORT_LOG_PREFIX {
                            tracing::debug!(
                                cid = %hex::encode(&report[0..4]),
                                cmd = %format_args!("{:#04x}", report[4]),
                                "hid report in"
                            );
                        }
                        let (responses, action) = transport.handle_report(&report);
                        write_all(&device, responses, &mut write_failures).await;
                        match action {
                            Some(CtapAction::Relay(payload)) => {
                                let Some(cid) = transport.busy_channel() else { continue };
                                if pending.is_some() {
                                    // A second single-frame CBOR command is
                                    // already rejected by the CTAPHID layer,
                                    // but a host can restart a multi-frame
                                    // assembly on the same channel: that
                                    // overwrites the pending one and, on
                                    // completion, clears `busy` first, so the
                                    // command reaches us while a transaction is
                                    // still pending. Refuse it and free the
                                    // slot, rather than dropping it and wedging
                                    // the channel until the host times out.
                                    tracing::warn!(
                                        "relay requested while a transaction is pending; refusing"
                                    );
                                    let reports = transport
                                        .complete_relay(cid, &[CTAP1_ERR_CHANNEL_BUSY]);
                                    write_all(&device, reports, &mut write_failures).await;
                                    continue;
                                }
                                // Follow-up to a faked preflight response that
                                // reported several credentials: serve the next
                                // one so Firefox keeps the whole allowList.
                                if payload == [CMD_GET_NEXT_ASSERTION] {
                                    let response = match fake_assertions.as_mut() {
                                        Some((rp, rest)) => match rest.pop_front() {
                                            Some(cred) => {
                                                ucabled::ctap::fake_next_assertion(rp, &cred)
                                            }
                                            None => vec![CTAP2_ERR_NOT_ALLOWED],
                                        },
                                        None => vec![CTAP2_ERR_NOT_ALLOWED],
                                    };
                                    let reports = transport.complete_relay(cid, &response);
                                    write_all(&device, reports, &mut write_failures).await;
                                    continue;
                                }
                                // Firefox probes with getAssertion up=false to
                                // filter the allowList to credentials present on
                                // this device. For a normal RP ID, answer locally
                                // with a fake success echoing the credential ID,
                                // so Firefox proceeds to the real interactive
                                // request without a pointless QR scan; an error
                                // answer here would make Firefox drop the device
                                // from the transaction entirely. The AppID probe
                                // below is the exception, where declining is
                                // instead the expected signal.
                                // Report *all* credentials and stash the rest for
                                // `getNextAssertion`: claiming only the first
                                // would narrow the real allowList to it.
                                if let Some((rp, response, rest)) =
                                    ucabled::ctap::answer_silent_probe(&payload)
                                {
                                    fake_assertions = None;
                                    // Firefox also sends this probe with the
                                    // legacy U2F AppID as the RP ID to discover
                                    // U2F credentials for the `appid` extension.
                                    // Claiming one would make Firefox address the
                                    // AppID for the real request, where the phone
                                    // (which stores passkeys by WebAuthn RP ID)
                                    // finds nothing. Decline so Firefox keeps the
                                    // WebAuthn RP ID.
                                    let response = if ucabled::ctap::is_u2f_appid(&rp) {
                                        tracing::info!("U2F AppID probe (up=false), declining");
                                        vec![CTAP2_ERR_NO_CREDENTIALS]
                                    } else {
                                        tracing::info!(
                                            credentials = rest.len() + 1,
                                            "silent probe (up=false), answering locally"
                                        );
                                        if !rest.is_empty() {
                                            fake_assertions = Some((rp, rest.into()));
                                        }
                                        response
                                    };
                                    let reports = transport.complete_relay(cid, &response);
                                    write_all(&device, reports, &mut write_failures).await;
                                    continue;
                                }
                                // Firefox's dummy makeCredential is how it
                                // asks the user to pick among several
                                // authenticators ("Multiple devices found").
                                // It only counts as "selected" if the device
                                // answers with a Pin* status, which a physical
                                // key only does once touched. Put the choice in
                                // the user's hands with our own window.
                                if ucabled::ctap::is_blink_probe(&payload) {
                                    if let Some(agent) = notifier.select(cid as u64) {
                                        tracing::info!("asking the user to choose the phone");
                                        pending = Some(Pending::Select {
                                            cid,
                                            deadline: tokio::time::Instant::now()
                                                + SELECT_TIMEOUT,
                                            agent: Some(agent),
                                        });
                                    } else {
                                        tracing::info!("blink probe, no UI available, declining");
                                        let reports = transport.complete_relay(cid, &[CTAP2_ERR_INVALID_OPTION]);
                                        write_all(&device, reports, &mut write_failures).await;
                                    }
                                    continue;
                                }
                                // Any preflight state is done with once the real
                                // request starts.
                                fake_assertions = None;
                                // One atomic read: availability and the
                                // generation tag share it, so an agent
                                // departing between the two cannot leave
                                // the transaction untagged.
                                let Some(ui) = notifier.ui_for_transaction() else {
                                    tracing::warn!(
                                        "no UI agent registered; refusing the transaction"
                                    );
                                    let reports = transport
                                        .complete_relay(cid, &[CTAP1_ERR_TIMEOUT]);
                                    write_all(&device, reports, &mut write_failures).await;
                                    continue;
                                };
                                let rp = ucabled::ctap::extract_rp_id(&payload);
                                tracing::info!(
                                    ?rp,
                                    cmd = %format_args!("{:#04x}", payload.first().copied().unwrap_or(0)),
                                    len = payload.len(),
                                    "starting caBLE transaction"
                                );
                                // iOS requires rp.name / user.displayName;
                                // inject them when Firefox omitted them.
                                let payload = ucabled::ctap::patch_makecredential(&payload);
                                // OpenSSH reuses one fixed user handle for
                                // every sk key; give each registration its
                                // own so the phone does not replace the
                                // previous passkey.
                                let payload = ucabled::ctap::dissociate_ssh_user(&payload);
                                // Firefox tags USB credentials with a
                                // transports hint that some phones reject.
                                let payload = ucabled::ctap::strip_transport_hints(&payload);
                                // Firefox sends getAssertion options out of
                                // canonical order, which Android rejects.
                                let payload = ucabled::ctap::normalize_assertion_options(&payload);
                                // The patchers borrow the original payload
                                // when nothing changed; the relay task is
                                // spawned and needs an owned buffer.
                                let payload = payload.into_owned();
                                let request_type = if payload.first() == Some(&CMD_MAKE_CREDENTIAL) {
                                    RequestType::MakeCredential
                                } else {
                                    RequestType::GetAssertion
                                };
                                let tx = result_tx.clone();
                                let notifier2 = notifier.clone();
                                let notifier3 = notifier.clone();
                                let identity = identity.clone();
                                let task = tokio::spawn(async move {
                                    let r = ucabled::relay::run_qr_transaction(
                                        &payload,
                                        request_type,
                                        &identity,
                                        move |url| {
                                            notifier2.show(
                                                cid as u64,
                                                url,
                                                rp,
                                                ucabled::relay::BLE_ADVERT_TIMEOUT.as_secs(),
                                                request_type,
                                            )
                                        },
                                        move || notifier3.phone_found(),
                                    )
                                    .await;
                                    let _ = tx.send((cid, r));
                                });
                                pending = Some(Pending::Relay {
                                    cid,
                                    abort: task.abort_handle(),
                                    agent: ui.generation(),
                                });
                            }
                            Some(CtapAction::CancelRelay) => match pending.take() {
                                Some(Pending::Relay { abort, .. }) => {
                                    abort.abort();
                                    notifier.hide();
                                    tracing::info!("cancelled caBLE transaction");
                                }
                                Some(Pending::Select { .. }) => {
                                    // The host cancelled because another
                                    // authenticator (the user touched it) won
                                    // the selection; drop our prompt.
                                    notifier.hide();
                                    tracing::info!("device selection cancelled by the host");
                                }
                                None => {}
                            },
                            None => {}
                        }
                    }
                    UhidEvent::Open => {
                        open_count += 1;
                        tracing::info!("hidraw opened by a process");
                    }
                    UhidEvent::Close => {
                        if open_count == 0 {
                            // Unbalanced close: the count no longer
                            // reflects reality (an Open was missed), so do
                            // not reset — that could cut off a live client
                            // whose open was never counted.
                            tracing::warn!("hidraw close without a matching open");
                            continue;
                        }
                        open_count -= 1;
                        tracing::info!(open_count, "hidraw closed");
                        if open_count == 0 {
                            // The last host handle is gone, possibly
                            // mid-message or mid-transaction: drop the
                            // partial state so a fresh opener does not
                            // inherit a wedged channel, and stop any work
                            // nobody is left to read the answer of.  This
                            // includes the silent-probe preflight cache,
                            // which must not leak across host clients.
                            transport.reset();
                            fake_assertions = None;
                            if let Some(p) = pending.take() {
                                if let Pending::Relay { abort, .. } = p {
                                    abort.abort();
                                }
                                notifier.hide();
                                tracing::info!(
                                    "last hidraw handle closed, dropped pending transaction"
                                );
                            }
                        }
                    }
                    UhidEvent::Start | UhidEvent::Stop => {}
                    UhidEvent::Other(t) => tracing::debug!(t, "unhandled uhid event"),
                }
            }
            Some((cid, result)) = result_rx.recv() => {
                if let Some(Pending::Relay { cid: pending_cid, .. }) = &pending
                    && *pending_cid == cid {
                        notifier.hide();
                        let payload = match result {
                            Ok(p) => {
                                tracing::info!(
                                    status = %format_args!("{:#04x}", p.first().copied().unwrap_or(0)),
                                    len = p.len(),
                                    "caBLE transaction completed"
                                );
                                p
                            }
                            Err(e) => {
                                tracing::warn!("caBLE transaction failed: {e}");
                                // A refused redirect means the tunnel server
                                // misbehaved — not a routine failure — so
                                // surface it to the user.
                                if e.is_redirect_refused() {
                                    notifier.notify(
                                        REDIRECT_REFUSED_SUMMARY,
                                        REDIRECT_REFUSED_BODY,
                                    );
                                }
                                vec![e.ctap_status()]
                            }
                        };
                        let reports = transport.complete_relay(cid, &payload);
                        write_all(&device, reports, &mut write_failures).await;
                        pending = None;
                    }
            }
            Some((tid, use_phone)) = select_rx.recv() => {
                if let Some(Pending::Select { cid, .. }) = &pending
                    && *cid as u64 == tid {
                        let cid = *cid;
                        pending = None;
                        // CTAP2_ERR_PIN_NOT_SET: on the blink probe a Pin*
                        // status tells authenticator-rs that this device was
                        // selected, so Firefox proceeds with the phone flow.
                        let status = if use_phone { CTAP2_ERR_PIN_NOT_SET } else { CTAP2_ERR_INVALID_OPTION };
                        let reports = transport.complete_relay(cid, &[status]);
                        write_all(&device, reports, &mut write_failures).await;
                        tracing::info!(use_phone, "device selection answered");
                    }
            }
            Some(request) = cancel_rx.recv() => {
                if !cancel_aborts(&request, pending.as_ref()) {
                    tracing::debug!(?request, "ignoring stale cancellation");
                    continue;
                }
                let Some(p) = pending.take() else {
                    continue;
                };
                match p {
                    Pending::Relay { cid, abort, .. } => {
                        abort.abort();
                        let reports = transport.cancel_relay(cid);
                        write_all(&device, reports, &mut write_failures).await;
                        tracing::info!(?request, "pending transaction cancelled");
                    }
                    // The selection window answers through SelectionResult,
                    // so a TransactionCancelled for its tid should never
                    // arrive; decline defensively if one does.
                    Pending::Select { cid, .. } => {
                        let reports =
                            transport.complete_relay(cid, &[CTAP2_ERR_INVALID_OPTION]);
                        write_all(&device, reports, &mut write_failures).await;
                        tracing::info!(?request, "pending device selection cancelled");
                    }
                }
            }
            // The keepalive cadence is only needed while a transaction is
            // pending or an unfinished assembly needs its idle-expiry check;
            // gating the branch keeps an idle daemon from waking ~7 times a
            // second for its whole lifetime.
            _ = keepalive.tick(), if pending.is_some() || transport.has_assembly() => {
                // A truncated multi-frame request must not wedge the busy
                // slot forever; hosts send continuation frames back to
                // back, so idle silence means the sender is gone.
                if transport.expire_assembly(std::time::Instant::now()) {
                    tracing::warn!("dropped an unfinished multi-frame request (idle timeout)");
                }
                let Some(p) = pending.as_ref() else { continue };
                let cid = p.cid();
                let timed_out = matches!(
                    p,
                    Pending::Select { deadline, .. }
                        if tokio::time::Instant::now() >= *deadline
                );
                if timed_out {
                    pending = None;
                    let reports = transport.complete_relay(cid, &[CTAP2_ERR_INVALID_OPTION]);
                    write_all(&device, reports, &mut write_failures).await;
                    tracing::warn!("device selection timed out, declining");
                } else {
                    let reports = transport.keepalive(cid);
                    write_all(&device, reports, &mut write_failures).await;
                }
            }
        }
    }
}

/// Write response reports to the host, tolerating transient failures so a
/// hiccup does not kill an in-flight transaction. Persistent failure is
/// handled by the read path, which eventually restarts the daemon.
async fn write_all(device: &UhidDevice, reports: Vec<Vec<u8>>, failures: &mut u32) {
    for r in reports {
        match device.write_input(&r).await {
            Ok(()) => *failures = 0,
            Err(e) => {
                *failures += 1;
                if *failures == 1 || failures.is_multiple_of(WRITE_FAILURE_LOG_EVERY) {
                    tracing::warn!("uhid write failed ({failures} times): {e}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn select_pending(cid: u32, agent: Option<u64>) -> Pending {
        Pending::Select {
            cid,
            deadline: tokio::time::Instant::now() + SELECT_TIMEOUT,
            agent,
        }
    }

    #[test]
    fn user_cancellation_matches_only_the_current_transaction() {
        let p = select_pending(7, Some(1));
        assert!(cancel_aborts(&CancelRequest::Transaction(7), Some(&p)));
        // Stale tid from an earlier, already-finished transaction.
        assert!(!cancel_aborts(&CancelRequest::Transaction(6), Some(&p)));
        // Nothing pending at all.
        assert!(!cancel_aborts(&CancelRequest::Transaction(7), None));
    }

    #[test]
    fn agent_gone_matches_only_the_owning_generation() {
        let p = select_pending(7, Some(3));
        assert!(cancel_aborts(&CancelRequest::AgentGone(3), Some(&p)));
        // A departed predecessor or a not-yet-seen successor must not
        // abort this transaction.
        assert!(!cancel_aborts(&CancelRequest::AgentGone(2), Some(&p)));
        assert!(!cancel_aborts(&CancelRequest::AgentGone(4), Some(&p)));
        assert!(!cancel_aborts(&CancelRequest::AgentGone(3), None));
    }

    #[test]
    fn agent_gone_does_not_touch_agentless_transactions() {
        // Terminal QR: no agent was involved, so no agent departure
        // applies.
        let p = select_pending(7, None);
        assert!(!cancel_aborts(&CancelRequest::AgentGone(1), Some(&p)));
    }

    // The timer needs a Tokio time context to be constructed.
    #[tokio::test]
    async fn keepalives_use_delay_not_burst() {
        // Burst would replay every tick missed during an idle interval at
        // once, flooding the host with keepalive reports.
        assert_eq!(
            keepalive_interval().missed_tick_behavior(),
            tokio::time::MissedTickBehavior::Delay
        );
    }
}
