use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::rpc_service::{AppState, current_time_secs};
use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use libp2p_metrics::Registry;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use store::{GraphStatus, InstanceBridgeInStatus, InstanceBridgeOutStatus, MessageState};
use tokio::time::Instant;

const METRICS_CONTENT_TYPE: &str = "application/openmetrics-text;charset=utf-8;version=1.0.0";

/// Creates a duration histogram using the shared HTTP and task latency buckets.
fn duration_histogram() -> Histogram {
    Histogram::new(exponential_buckets(0.005, 2.0, 15))
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct HttpRequestLabels {
    method: String,
    route: String,
    status: u16,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct HttpRouteLabels {
    method: String,
    route: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct TaskOutcomeLabels {
    task: String,
    outcome: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct TaskLabels {
    task: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct MessageDispatchLabels {
    message_type: String,
    outcome: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct InstanceLabels {
    flow: String,
    status: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct StatusLabels {
    status: String,
}

#[derive(Clone, Debug)]
pub struct MetricsState {
    pub registry: Arc<Mutex<Registry>>,
    http_requests_total: Family<HttpRequestLabels, Counter>,
    http_request_duration_seconds: Family<HttpRouteLabels, Histogram>,
    http_requests_in_flight: Gauge,
    task_runs_total: Family<TaskOutcomeLabels, Counter>,
    task_duration_seconds: Family<TaskLabels, Histogram>,
    task_last_success_timestamp_seconds: Family<TaskLabels, Gauge>,
    message_dispatch_total: Family<MessageDispatchLabels, Counter>,
    instances: Family<InstanceLabels, Gauge>,
    graphs: Family<StatusLabels, Gauge>,
    messages: Family<StatusLabels, Gauge>,
    oldest_pending_message_age_seconds: Gauge,
}

struct InFlightGuard(Gauge);

impl Drop for InFlightGuard {
    /// Decrements the in-flight request gauge when request processing ends or is cancelled.
    fn drop(&mut self) {
        self.0.dec();
    }
}

impl MetricsState {
    pub fn new(registry: Arc<Mutex<Registry>>) -> Self {
        let http_requests_total = Family::default();
        let http_request_duration_seconds: Family<HttpRouteLabels, Histogram> =
            Family::new_with_constructor(duration_histogram);
        let http_requests_in_flight = Gauge::default();
        let task_runs_total = Family::default();
        let task_duration_seconds: Family<TaskLabels, Histogram> =
            Family::new_with_constructor(duration_histogram);
        let task_last_success_timestamp_seconds = Family::default();
        let message_dispatch_total = Family::default();
        let instances = Family::default();
        let graphs = Family::default();
        let messages = Family::default();
        let oldest_pending_message_age_seconds = Gauge::default();

        {
            let mut registry = registry.lock().unwrap();
            registry.register(
                "http_requests",
                "Total number of HTTP requests",
                http_requests_total.clone(),
            );
            registry.register(
                "http_request_duration_seconds",
                "HTTP request duration in seconds",
                http_request_duration_seconds.clone(),
            );
            registry.register(
                "http_requests_in_flight",
                "Number of HTTP requests currently being processed",
                http_requests_in_flight.clone(),
            );
            registry.register(
                "bitvm_node_task_runs",
                "Total number of node task runs",
                task_runs_total.clone(),
            );
            registry.register(
                "bitvm_node_task_duration_seconds",
                "Node task duration in seconds",
                task_duration_seconds.clone(),
            );
            registry.register(
                "bitvm_node_task_last_success_timestamp_seconds",
                "Unix timestamp of the last successful node task run",
                task_last_success_timestamp_seconds.clone(),
            );
            registry.register(
                "bitvm_node_message_dispatch",
                "Total number of protocol message dispatches",
                message_dispatch_total.clone(),
            );
            registry.register(
                "bitvm_node_instances",
                "Number of bridge instances by flow and status",
                instances.clone(),
            );
            registry.register("bitvm_node_graphs", "Number of graphs by status", graphs.clone());
            registry.register(
                "bitvm_node_messages",
                "Number of queued messages by state",
                messages.clone(),
            );
            registry.register(
                "bitvm_node_oldest_pending_message_age_seconds",
                "Age in seconds of the oldest pending message",
                oldest_pending_message_age_seconds.clone(),
            );
        }

        Self {
            registry,
            http_requests_total,
            http_request_duration_seconds,
            http_requests_in_flight,
            task_runs_total,
            task_duration_seconds,
            task_last_success_timestamp_seconds,
            message_dispatch_total,
            instances,
            graphs,
            messages,
            oldest_pending_message_age_seconds,
        }
    }

    /// Records a task outcome and duration, updating its success timestamp when applicable.
    pub fn record_task_run(&self, task: &str, outcome: &str, duration: Duration) {
        self.task_runs_total
            .get_or_create(&TaskOutcomeLabels {
                task: task.to_owned(),
                outcome: outcome.to_owned(),
            })
            .inc();
        self.task_duration_seconds
            .get_or_create(&TaskLabels { task: task.to_owned() })
            .observe(duration.as_secs_f64());
        if outcome == "success" {
            self.task_last_success_timestamp_seconds
                .get_or_create(&TaskLabels { task: task.to_owned() })
                .set(current_time_secs());
        }
    }

    /// Records the outcome of dispatching a decoded protocol message.
    pub fn record_message_dispatch(&self, message_type: &str, outcome: &str) {
        self.message_dispatch_total
            .get_or_create(&MessageDispatchLabels {
                message_type: message_type.to_owned(),
                outcome: outcome.to_owned(),
            })
            .inc();
    }

    /// Replaces the exported database gauges with the latest grouped state counts.
    fn apply_database_metrics(&self, counts: &[store::MetricsStateCount]) {
        self.instances.clear();
        self.graphs.clear();
        self.messages.clear();
        self.oldest_pending_message_age_seconds.set(0);
        let now = current_time_secs();

        for count in counts {
            match count.category.as_str() {
                "instance_bridge_in" => {
                    let status = known_status::<InstanceBridgeInStatus>(&count.state);
                    self.instances
                        .get_or_create(&InstanceLabels { flow: "bridge_in".to_string(), status })
                        .inc_by(count.count);
                }
                "instance_bridge_out" => {
                    let status = known_status::<InstanceBridgeOutStatus>(&count.state);
                    self.instances
                        .get_or_create(&InstanceLabels { flow: "bridge_out".to_string(), status })
                        .inc_by(count.count);
                }
                "graph" => {
                    let status = known_status::<GraphStatus>(&count.state);
                    self.graphs.get_or_create(&StatusLabels { status }).inc_by(count.count);
                }
                "message" => {
                    let status = known_status::<MessageState>(&count.state);
                    self.messages
                        .get_or_create(&StatusLabels { status: status.clone() })
                        .inc_by(count.count);
                    if status == "Pending" {
                        self.oldest_pending_message_age_seconds.set(
                            count
                                .oldest_created_at
                                .map_or(0, |created_at| now.saturating_sub(created_at).max(0)),
                        );
                    }
                }
                _ => {}
            }
        }
    }
}

/// Returns a bounded status label, mapping unexpected database values to `unknown`.
fn known_status<T: FromStr>(state: &str) -> String {
    if state.parse::<T>().is_ok() { state.to_owned() } else { "unknown".to_string() }
}

pub async fn metrics_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    let start = Instant::now();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_string(), |route| route.as_str().to_owned());
    let method = request.method().to_string();

    state.metrics_state.http_requests_in_flight.inc();
    let in_flight = InFlightGuard(state.metrics_state.http_requests_in_flight.clone());
    let response = next.run(request).await;
    drop(in_flight);

    let status = response.status().as_u16();
    state
        .metrics_state
        .http_requests_total
        .get_or_create(&HttpRequestLabels { method: method.clone(), route: route.clone(), status })
        .inc();
    state
        .metrics_state
        .http_request_duration_seconds
        .get_or_create(&HttpRouteLabels { method, route })
        .observe(start.elapsed().as_secs_f64());
    response
}

/// Refreshes database-backed gauges and returns the encoded metrics response.
pub async fn metrics_handler(State(app_state): State<Arc<AppState>>) -> Response {
    let counts = match app_state.local_db.acquire().await {
        Ok(mut storage) => storage.node_metrics_state_counts().await,
        Err(error) => Err(error),
    };
    let counts = match counts {
        Ok(counts) => counts,
        Err(error) => {
            tracing::error!(error = %error, "failed to collect node database metrics");
            return (StatusCode::SERVICE_UNAVAILABLE, "metrics unavailable\n").into_response();
        }
    };

    let mut buffer = String::new();
    let registry = app_state.metrics_state.registry.lock().unwrap();
    app_state.metrics_state.apply_database_metrics(&counts);
    if let Err(error) = encode(&mut buffer, &registry) {
        tracing::error!(error = %error, "failed to encode node metrics");
        return (StatusCode::INTERNAL_SERVER_ERROR, "metrics encoding failed\n").into_response();
    }

    let mut headers = HeaderMap::new();
    headers.insert(axum::http::header::CONTENT_TYPE, METRICS_CONTENT_TYPE.parse().unwrap());
    (StatusCode::OK, headers, buffer).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus_client::encoding::text::encode;

    fn encoded(state: &MetricsState) -> String {
        let mut output = String::new();
        encode(&mut output, &state.registry.lock().unwrap()).unwrap();
        output
    }

    #[test]
    fn exports_correct_counter_name_and_bounded_database_labels() {
        let state = MetricsState::new(Arc::new(Mutex::new(Registry::default())));
        state
            .http_requests_total
            .get_or_create(&HttpRequestLabels {
                method: "GET".to_string(),
                route: "unmatched".to_string(),
                status: 404,
            })
            .inc();
        state.apply_database_metrics(&[
            store::MetricsStateCount {
                category: "graph".to_string(),
                state: "unexpected-id-like-value".to_string(),
                count: 1,
                oldest_created_at: None,
                last_success_at: None,
            },
            store::MetricsStateCount {
                category: "graph".to_string(),
                state: "another-unexpected-value".to_string(),
                count: 2,
                oldest_created_at: None,
                last_success_at: None,
            },
        ]);

        let output = encoded(&state);
        assert!(output.contains("http_requests_total"));
        assert!(!output.contains("http_requests_total_total"));
        assert!(output.contains("route=\"unmatched\""));
        assert!(output.contains("bitvm_node_graphs{status=\"unknown\"} 3"));
        assert!(!output.contains("bitvm_node_graphs{status=\"OperatorPresigned\"}"));
        assert!(!output.contains("unexpected-id-like-value"));
        assert!(!output.contains("another-unexpected-value"));
    }

    #[test]
    fn records_task_and_message_metrics() {
        let state = MetricsState::new(Arc::new(Mutex::new(Registry::default())));
        state.record_task_run("maintenance", "success", Duration::from_millis(25));
        state.record_task_run("history_sync", "deferred", Duration::from_millis(5));
        state.record_message_dispatch("Tick", "success");

        let output = encoded(&state);
        assert!(
            output
                .contains("bitvm_node_task_runs_total{task=\"maintenance\",outcome=\"success\"} 1")
        );
        assert!(output.contains(
            "bitvm_node_message_dispatch_total{message_type=\"Tick\",outcome=\"success\"} 1"
        ));
        assert!(
            !output
                .contains("bitvm_node_task_last_success_timestamp_seconds{task=\"history_sync\"}")
        );
    }
}
