use prometheus::{
    register_counter_vec, register_histogram_vec, register_int_gauge, Counter, CounterVec, Encoder,
    HistogramVec, IntGauge, TextEncoder,
};
use std::net::SocketAddr;
use std::sync::LazyLock;

/// Number of active QUIC connections.
pub static ACTIVE_CONNECTIONS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "pike_active_connections",
        "Number of active QUIC connections"
    )
    .expect("register pike_active_connections metric")
});

/// Number of active tunnels.
pub static ACTIVE_TUNNELS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!("pike_active_tunnels", "Number of active tunnels")
        .expect("register pike_active_tunnels metric")
});

/// Total bytes transferred, labeled by direction: "in" or "out".
pub static BYTES_TRANSFERRED: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "pike_bytes_transferred",
        "Total bytes transferred",
        &["direction"]
    )
    .expect("register pike_bytes_transferred metric")
});

/// Request latency histogram, labeled by tunnel type: "http" or "tcp".
pub static REQUEST_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "pike_request_latency_seconds",
        "Request latency in seconds",
        &["tunnel_type"],
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
    )
    .expect("register pike_request_latency_seconds metric")
});

/// Error rate counter, labeled by error type.
pub static ERROR_RATE: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "pike_errors_total",
        "Total number of errors",
        &["error_type"]
    )
    .expect("register pike_errors_total metric")
});

pub static RATE_LIMIT_REJECTIONS: LazyLock<Counter> = LazyLock::new(|| {
    prometheus::register_counter!(
        "pike_rate_limit_rejections_total",
        "Total number of requests rejected by the per-IP rate limiter"
    )
    .expect("register pike_rate_limit_rejections_total metric")
});

/// Metrics HTTP handler that returns Prometheus-formatted metrics
pub async fn metrics_handler() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder
        .encode(&metric_families, &mut buffer)
        .unwrap_or_else(|_| {
            // Fallback if encoding fails
            buffer.clear();
        });
    String::from_utf8(buffer).unwrap_or_else(|_| "Failed to encode metrics".to_string())
}

/// Start the metrics HTTP server on the specified address
pub async fn start_metrics_server(bind_addr: SocketAddr) -> anyhow::Result<()> {
    use axum::routing::get;
    use axum::Router;

    let app = Router::new().route("/metrics", get(metrics_handler));

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind metrics server on {}: {}", bind_addr, e))?;

    tracing::info!(bind_addr = %bind_addr, "Metrics listener ready");

    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow::anyhow!("metrics server terminated unexpectedly: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gather_family(name: &str) -> prometheus::proto::MetricFamily {
        let families = prometheus::gather();
        families
            .into_iter()
            .find(|family| family.get_name() == name)
            .unwrap_or_else(|| panic!("missing metric family: {name}"))
    }

    #[test]
    fn test_metrics_initialization() {
        ACTIVE_CONNECTIONS.set(0);
        ACTIVE_TUNNELS.set(0);

        assert_eq!(ACTIVE_CONNECTIONS.get(), 0);
        assert_eq!(ACTIVE_TUNNELS.get(), 0);
    }

    #[test]
    fn test_active_connections_metric() {
        ACTIVE_CONNECTIONS.set(5);
        assert_eq!(ACTIVE_CONNECTIONS.get(), 5);

        ACTIVE_CONNECTIONS.inc();
        assert_eq!(ACTIVE_CONNECTIONS.get(), 6);

        ACTIVE_CONNECTIONS.dec();
        assert_eq!(ACTIVE_CONNECTIONS.get(), 5);

        ACTIVE_CONNECTIONS.set(0);
    }

    #[test]
    fn test_active_tunnels_metric() {
        ACTIVE_TUNNELS.set(3);
        assert_eq!(ACTIVE_TUNNELS.get(), 3);

        ACTIVE_TUNNELS.inc();
        assert_eq!(ACTIVE_TUNNELS.get(), 4);

        ACTIVE_TUNNELS.dec();
        assert_eq!(ACTIVE_TUNNELS.get(), 3);

        ACTIVE_TUNNELS.set(0);
    }

    #[test]
    fn test_bytes_transferred_metric() {
        let in_counter = BYTES_TRANSFERRED.with_label_values(&["in"]);
        let out_counter = BYTES_TRANSFERRED.with_label_values(&["out"]);

        in_counter.inc_by(1024.0);
        out_counter.inc_by(2048.0);

        let family = gather_family("pike_bytes_transferred");
        let mut seen_in = false;
        let mut seen_out = false;

        for metric in family.get_metric() {
            let labels: std::collections::HashMap<_, _> = metric
                .get_label()
                .iter()
                .map(|l| (l.get_name(), l.get_value()))
                .collect();
            let direction = labels.get("direction").copied().unwrap_or_default();

            if direction == "in" {
                seen_in = true;
                assert!(metric.get_counter().get_value() >= 1024.0);
            }
            if direction == "out" {
                seen_out = true;
                assert!(metric.get_counter().get_value() >= 2048.0);
            }
        }

        assert!(seen_in);
        assert!(seen_out);
    }

    #[test]
    fn test_request_latency_metric() {
        let http_histogram = REQUEST_LATENCY.with_label_values(&["http"]);
        let tcp_histogram = REQUEST_LATENCY.with_label_values(&["tcp"]);

        http_histogram.observe(0.05);
        tcp_histogram.observe(0.1);

        let family = gather_family("pike_request_latency_seconds");
        assert!(!family.get_metric().is_empty());
        assert!(family
            .get_metric()
            .iter()
            .any(|m| m.get_histogram().get_sample_count() >= 1));
    }

    #[test]
    fn test_error_rate_metric() {
        let connection_error = ERROR_RATE.with_label_values(&["connection"]);
        let timeout_error = ERROR_RATE.with_label_values(&["timeout"]);

        connection_error.inc();
        timeout_error.inc_by(2.0);

        let family = gather_family("pike_errors_total");
        assert!(family
            .get_metric()
            .iter()
            .any(|m| m.get_counter().get_value() >= 1.0));
    }

    #[tokio::test]
    async fn test_metrics_handler_returns_string() {
        let output = metrics_handler().await;
        assert!(!output.is_empty());
        assert!(output.contains("pike_active_connections") || output.contains("# HELP"));
    }

    #[tokio::test]
    async fn test_metrics_endpoint_returns_prometheus_format() {
        let _ = &*ACTIVE_CONNECTIONS;
        let _ = &*ACTIVE_TUNNELS;
        let _ = &*RATE_LIMIT_REJECTIONS;
        let output = metrics_handler().await;
        assert!(
            output.contains("# HELP pike_active_connections"),
            "expected # HELP pike_active_connections in output"
        );
        assert!(
            output.contains("# HELP pike_rate_limit_rejections_total"),
            "expected # HELP pike_rate_limit_rejections_total in output"
        );
    }
}
