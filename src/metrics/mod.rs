//! Prometheus metrics for SIPhon.
//!
//! Exposes counters, histograms, and gauges for SIP traffic, transactions,
//! registrations, dialogs, and transport connections. Metrics are collected
//! inline (at the call site) and scraped via the HTTP admin API `/metrics`.

use prometheus::{
    Encoder, Gauge, GaugeVec, HistogramOpts, HistogramVec, IntCounter, IntCounterVec,
    IntGauge, Opts, Registry, TextEncoder,
};
use std::sync::OnceLock;

/// Global metrics registry — initialized once at startup.
static METRICS: OnceLock<SiphonMetrics> = OnceLock::new();

/// Access the global metrics instance. Panics if not initialized.
pub fn metrics() -> &'static SiphonMetrics {
    METRICS.get().expect("metrics not initialized — call metrics::init() at startup")
}

/// Try to access the global metrics (returns None before init).
pub fn try_metrics() -> Option<&'static SiphonMetrics> {
    METRICS.get()
}

/// Initialize the global metrics. Call once at startup.
pub fn init() {
    METRICS.get_or_init(SiphonMetrics::new);
}

/// All SIPhon metrics in one struct for easy access.
pub struct SiphonMetrics {
    pub registry: Registry,

    // --- Request counters ---
    pub requests_total: IntCounterVec,
    pub responses_total: IntCounterVec,

    // --- Transaction gauges ---
    pub transactions_active: IntGauge,

    // --- Registration gauges ---
    pub registrations_active: IntGauge,

    // --- Dialog gauges ---
    pub dialogs_active: IntGauge,

    // --- Connection gauges ---
    pub connections_active: GaugeVec,

    // --- Duration histograms ---
    pub request_duration_seconds: HistogramVec,
    pub transaction_duration_seconds: HistogramVec,

    // --- Uptime ---
    pub uptime_seconds: Gauge,

    // --- Script execution ---
    pub script_executions_total: IntCounterVec,
    pub script_errors_total: IntCounter,
}

impl SiphonMetrics {
    fn new() -> Self {
        let registry = Registry::new();

        let requests_total = IntCounterVec::new(
            Opts::new("siphon_requests_total", "Total SIP requests received"),
            &["method"],
        )
        .unwrap();

        let responses_total = IntCounterVec::new(
            Opts::new("siphon_responses_total", "Total SIP responses sent"),
            &["code"],
        )
        .unwrap();

        let transactions_active = IntGauge::new(
            "siphon_transactions_active",
            "Number of active SIP transactions",
        )
        .unwrap();

        let registrations_active = IntGauge::new(
            "siphon_registrations_active",
            "Number of active registrations (AoR bindings)",
        )
        .unwrap();

        let dialogs_active = IntGauge::new(
            "siphon_dialogs_active",
            "Number of active SIP dialogs",
        )
        .unwrap();

        let connections_active = GaugeVec::new(
            Opts::new("siphon_connections_active", "Active transport connections"),
            &["transport"],
        )
        .unwrap();

        let request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "siphon_request_duration_seconds",
                "Request processing duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]),
            &["method"],
        )
        .unwrap();

        let transaction_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "siphon_transaction_duration_seconds",
                "SIP transaction duration from creation to completion",
            )
            .buckets(vec![0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 16.0, 32.0]),
            &["method", "type"],
        )
        .unwrap();

        let uptime_seconds = Gauge::new(
            "siphon_uptime_seconds",
            "Time since SIPhon process started",
        )
        .unwrap();

        let script_executions_total = IntCounterVec::new(
            Opts::new("siphon_script_executions_total", "Total Python script handler executions"),
            &["handler"],
        )
        .unwrap();

        let script_errors_total = IntCounter::new(
            "siphon_script_errors_total",
            "Total Python script execution errors",
        )
        .unwrap();

        // Register all metrics
        registry.register(Box::new(requests_total.clone())).unwrap();
        registry.register(Box::new(responses_total.clone())).unwrap();
        registry.register(Box::new(transactions_active.clone())).unwrap();
        registry.register(Box::new(registrations_active.clone())).unwrap();
        registry.register(Box::new(dialogs_active.clone())).unwrap();
        registry.register(Box::new(connections_active.clone())).unwrap();
        registry.register(Box::new(request_duration_seconds.clone())).unwrap();
        registry.register(Box::new(transaction_duration_seconds.clone())).unwrap();
        registry.register(Box::new(uptime_seconds.clone())).unwrap();
        registry.register(Box::new(script_executions_total.clone())).unwrap();
        registry.register(Box::new(script_errors_total.clone())).unwrap();

        Self {
            registry,
            requests_total,
            responses_total,
            transactions_active,
            registrations_active,
            dialogs_active,
            connections_active,
            request_duration_seconds,
            transaction_duration_seconds,
            uptime_seconds,
            script_executions_total,
            script_errors_total,
        }
    }
}

/// Encode all metrics as Prometheus text format.
pub fn encode_metrics() -> String {
    let metrics = metrics();
    let encoder = TextEncoder::new();
    let metric_families = metrics.registry.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_init_and_access() {
        init();
        let metrics = metrics();

        // Increment a counter
        metrics.requests_total.with_label_values(&["INVITE"]).inc();
        metrics.requests_total.with_label_values(&["REGISTER"]).inc();
        metrics.requests_total.with_label_values(&["INVITE"]).inc();

        assert_eq!(
            metrics.requests_total.with_label_values(&["INVITE"]).get(),
            2
        );
        assert_eq!(
            metrics.requests_total.with_label_values(&["REGISTER"]).get(),
            1
        );
    }

    #[test]
    fn metrics_encode_produces_text() {
        init();
        // Ensure at least one label is observed so the counter appears in output
        metrics().requests_total.with_label_values(&["OPTIONS"]).inc();
        let output = encode_metrics();
        // Gauges always appear (even at zero), counters appear after first observation
        assert!(output.contains("siphon_transactions_active"), "output: {}", &output[..output.len().min(500)]);
        assert!(output.contains("siphon_registrations_active"));
    }

    #[test]
    fn gauge_operations() {
        init();
        let metrics = metrics();

        metrics.transactions_active.set(5);
        assert_eq!(metrics.transactions_active.get(), 5);

        metrics.transactions_active.inc();
        assert_eq!(metrics.transactions_active.get(), 6);

        metrics.transactions_active.dec();
        assert_eq!(metrics.transactions_active.get(), 5);
    }

    #[test]
    fn connection_gauge_by_transport() {
        init();
        let metrics = metrics();

        metrics.connections_active.with_label_values(&["TCP"]).set(10.0);
        metrics.connections_active.with_label_values(&["UDP"]).set(0.0);
        metrics.connections_active.with_label_values(&["TLS"]).set(3.0);

        assert_eq!(
            metrics.connections_active.with_label_values(&["TCP"]).get(),
            10.0
        );
    }

    #[test]
    fn histogram_observation() {
        init();
        let metrics = metrics();

        metrics
            .request_duration_seconds
            .with_label_values(&["INVITE"])
            .observe(0.042);
        metrics
            .request_duration_seconds
            .with_label_values(&["REGISTER"])
            .observe(0.001);

        let output = encode_metrics();
        assert!(output.contains("siphon_request_duration_seconds"));
    }
}
