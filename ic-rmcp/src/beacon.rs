//! Usage reporting for MCP servers in the Prometheus Protocol ecosystem.
//!
//! The beacon keeps a small in-memory aggregate of tool calls and periodically
//! sends a Candid-compatible [`UsageStats`] value to a tracker canister. The
//! module is deliberately independent from [`crate::Handler`], so applications
//! can decide where authentication and tool dispatch should call [`track_call`].

use candid::{CandidType, Int, Nat, Principal};
use ic_cdk::call::Call;
use ic_cdk_timers::{clear_timer, set_timer_interval, TimerId};
use serde::Deserialize;
use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::mem;
use std::rc::Rc;
use std::time::Duration;

/// The default reporting period used when [`init`] receives `None`.
pub const DEFAULT_REPORTING_INTERVAL_SECONDS: u64 = 60 * 60;

/// One caller's usage of one MCP tool during a reporting window.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct CallerActivity {
    /// Principal that invoked the tool.
    pub caller: Principal,
    /// Application-defined MCP tool name or identifier.
    pub tool_id: String,
    /// Number of calls made by `caller` to `tool_id`.
    pub call_count: Nat,
}

/// Usage payload accepted by the Prometheus UsageTracker canister.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct UsageStats {
    /// Start of the reporting window, in IC nanoseconds.
    pub start_timestamp_ns: Int,
    /// End of the reporting window, in IC nanoseconds.
    pub end_timestamp_ns: Int,
    /// Aggregated caller/tool activity for the window.
    pub activity: Vec<CallerActivity>,
}

struct BeaconState {
    usage_data: HashMap<Principal, HashMap<String, u64>>,
    last_send_timestamp_ns: i64,
}

/// Mutable state and configuration for a usage beacon.
///
/// The state is shared with the timer callback through an `Rc`, which keeps
/// [`track_call`] synchronous and avoids holding a borrow across the async
/// inter-canister call. Timer registrations are not persisted across canister
/// upgrades; applications should call [`start_timer`] after an upgrade.
pub struct BeaconContext {
    state: Rc<RefCell<BeaconState>>,
    timer_id: Option<TimerId>,
    tracker_canister_id: Principal,
    reporting_interval_seconds: u64,
}

impl Drop for BeaconContext {
    fn drop(&mut self) {
        if let Some(timer_id) = self.timer_id.take() {
            clear_timer(timer_id);
        }
    }
}

/// Creates an empty beacon context.
///
/// `reporting_interval_seconds` defaults to one hour when omitted. A zero
/// interval is normalized to one second to avoid registering a continuously
/// firing global timer by accident.
pub fn init(
    tracker_canister_id: Principal,
    reporting_interval_seconds: Option<u64>,
) -> BeaconContext {
    BeaconContext {
        state: Rc::new(RefCell::new(BeaconState {
            usage_data: HashMap::new(),
            last_send_timestamp_ns: 0,
        })),
        timer_id: None,
        tracker_canister_id,
        reporting_interval_seconds: reporting_interval_seconds
            .unwrap_or(DEFAULT_REPORTING_INTERVAL_SECONDS)
            .max(1),
    }
}

/// Adds one invocation to the current reporting window.
pub fn track_call(context: &BeaconContext, caller: Principal, tool_id: impl Into<String>) {
    let mut state = context.state.borrow_mut();
    let calls_by_tool = state.usage_data.entry(caller).or_default();
    let count = calls_by_tool.entry(tool_id.into()).or_default();
    *count = count.saturating_add(1);
}

/// Starts or restarts the recurring usage-report timer.
///
/// Restarting first cancels the previous timer, which makes this safe to call
/// after canister initialization code is re-run. The callback never holds a
/// `RefCell` borrow while awaiting the tracker call.
pub fn start_timer(context: &mut BeaconContext) {
    if let Some(timer_id) = context.timer_id.take() {
        clear_timer(timer_id);
    }

    let now = ic_cdk::api::time() as i64;
    let mut state = context.state.borrow_mut();
    state.last_send_timestamp_ns = state.last_send_timestamp_ns.max(now);
    drop(state);

    let state = Rc::clone(&context.state);
    let tracker_canister_id = context.tracker_canister_id;
    let interval = Duration::from_secs(context.reporting_interval_seconds);
    context.timer_id = Some(set_timer_interval(interval, move || {
        let state = Rc::clone(&state);
        let tracker_canister_id = tracker_canister_id;
        ic_cdk::futures::spawn(async move {
            if let Err(error) = send_beacon(state, tracker_canister_id).await {
                ic_cdk::println!("Prometheus usage beacon failed: {error}");
            }
        });
    }));
}

struct PendingReport {
    usage_data: HashMap<Principal, HashMap<String, u64>>,
    stats: UsageStats,
}

fn take_report(state: &Rc<RefCell<BeaconState>>, end_timestamp_ns: i64) -> Option<PendingReport> {
    let (usage_data, start_timestamp_ns) = {
        let mut state = state.borrow_mut();
        if state.usage_data.is_empty() {
            return None;
        }
        (
            mem::take(&mut state.usage_data),
            state.last_send_timestamp_ns,
        )
    };

    let activity = usage_data
        .iter()
        .flat_map(|(caller, tools)| {
            tools.iter().map(|(tool_id, call_count)| CallerActivity {
                caller: *caller,
                tool_id: tool_id.clone(),
                call_count: Nat::from(*call_count),
            })
        })
        .collect();

    Some(PendingReport {
        usage_data,
        stats: UsageStats {
            start_timestamp_ns: Int::from(start_timestamp_ns),
            end_timestamp_ns: Int::from(end_timestamp_ns),
            activity,
        },
    })
}

fn restore_usage(
    state: &Rc<RefCell<BeaconState>>,
    usage_data: HashMap<Principal, HashMap<String, u64>>,
) {
    let mut state = state.borrow_mut();
    for (caller, tools) in usage_data {
        let current_tools = state.usage_data.entry(caller).or_default();
        for (tool_id, count) in tools {
            let current_count = current_tools.entry(tool_id).or_default();
            *current_count = current_count.saturating_add(count);
        }
    }
}

async fn send_report_with<F, Fut>(
    state: Rc<RefCell<BeaconState>>,
    tracker_canister_id: Principal,
    end_timestamp_ns: i64,
    sender: F,
) -> Result<(), String>
where
    F: FnOnce(Principal, UsageStats) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let report = match take_report(&state, end_timestamp_ns) {
        Some(report) => report,
        None => return Ok(()),
    };
    let last_send_timestamp_ns = end_timestamp_ns;

    match sender(tracker_canister_id, report.stats).await {
        Ok(()) => {
            let mut state = state.borrow_mut();
            state.last_send_timestamp_ns = state.last_send_timestamp_ns.max(last_send_timestamp_ns);
            Ok(())
        }
        Err(error) => {
            restore_usage(&state, report.usage_data);
            Err(error)
        }
    }
}

async fn send_beacon(
    state: Rc<RefCell<BeaconState>>,
    tracker_canister_id: Principal,
) -> Result<(), String> {
    let end_timestamp_ns = ic_cdk::api::time() as i64;
    send_report_with(
        state,
        tracker_canister_id,
        end_timestamp_ns,
        |tracker_canister_id, stats| async move {
            let response = Call::bounded_wait(tracker_canister_id, "log_call")
                .with_arg(stats)
                .await
                .map_err(|error| error.to_string())?;
            response
                .candid::<Result<(), String>>()
                .map_err(|error| error.to_string())?
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;

    #[test]
    fn track_call_aggregates_by_caller_and_tool() {
        let context = init(Principal::anonymous(), Some(60));
        let caller = Principal::from_text("2vxsx-fae").unwrap();

        track_call(&context, caller, "search");
        track_call(&context, caller, "search");
        track_call(&context, caller, "read");

        let state = context.state.borrow();
        let calls = state
            .usage_data
            .get(&Principal::from_text("2vxsx-fae").unwrap());
        assert_eq!(calls.and_then(|tools| tools.get("search")), Some(&2));
        assert_eq!(calls.and_then(|tools| tools.get("read")), Some(&1));
    }

    #[test]
    fn successful_delivery_sends_the_expected_payload_and_commits_timestamp() {
        let tracker = Principal::from_text("aaaaa-aa").unwrap();
        let context = init(tracker, Some(60));
        context.state.borrow_mut().last_send_timestamp_ns = 10;
        track_call(
            &context,
            Principal::from_text("2vxsx-fae").unwrap(),
            "search",
        );
        track_call(
            &context,
            Principal::from_text("2vxsx-fae").unwrap(),
            "search",
        );

        let captured = Rc::new(RefCell::new(None));
        let captured_for_sender = Rc::clone(&captured);
        let result = block_on(send_report_with(
            Rc::clone(&context.state),
            tracker,
            25,
            move |called_tracker, stats| {
                *captured_for_sender.borrow_mut() = Some((called_tracker, stats));
                async { Ok(()) }
            },
        ));

        assert_eq!(result, Ok(()));
        let (called_tracker, stats) = captured.borrow_mut().take().unwrap();
        assert_eq!(called_tracker, tracker);
        assert_eq!(stats.start_timestamp_ns, Int::from(10));
        assert_eq!(stats.end_timestamp_ns, Int::from(25));
        assert_eq!(stats.activity.len(), 1);
        assert_eq!(stats.activity[0].tool_id, "search");
        assert_eq!(stats.activity[0].call_count, Nat::from(2u64));
        assert!(context.state.borrow().usage_data.is_empty());
        assert_eq!(context.state.borrow().last_send_timestamp_ns, 25);
    }

    #[test]
    fn failed_delivery_restores_usage_for_the_next_attempt() {
        let context = init(Principal::anonymous(), Some(60));
        let caller = Principal::from_text("2vxsx-fae").unwrap();
        track_call(&context, caller, "search");

        let result = block_on(send_report_with(
            Rc::clone(&context.state),
            Principal::anonymous(),
            25,
            |_tracker, _stats| async { Err("tracker rejected the report".to_string()) },
        ));

        assert_eq!(result, Err("tracker rejected the report".to_string()));
        let state = context.state.borrow();
        assert_eq!(
            state
                .usage_data
                .get(&caller)
                .and_then(|tools| tools.get("search")),
            Some(&1)
        );
        assert_eq!(state.last_send_timestamp_ns, 0);
    }

    #[test]
    fn usage_stats_round_trips_as_unbounded_candid_numbers() {
        let stats = UsageStats {
            start_timestamp_ns: Int::from(-10),
            end_timestamp_ns: Int::from(25),
            activity: vec![CallerActivity {
                caller: Principal::from_text("2vxsx-fae").unwrap(),
                tool_id: "search".to_string(),
                call_count: Nat::from(u64::MAX),
            }],
        };

        let encoded = candid::encode_one(&stats).unwrap();
        let decoded: UsageStats = candid::decode_one(&encoded).unwrap();

        assert_eq!(decoded, stats);
    }
}
