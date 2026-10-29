"""
H07 in-process observability — Prometheus counters/gauges/histograms.

Scope (brief H07): the golden metrics that are OBSERVED INSIDE the engine
process. DB-sourced gauges (worker heartbeats, oldest outbox age, chain
submission depth) are sampled at scrape time in
app/routes/internal/metrics.py from the SAME tables the R08 workers write —
this module only carries the registry and the in-process instruments.

No-PII rule (brief, binding): every label below is a route TEMPLATE
(e.g. /api/v2/cases/{case_id}), an HTTP method, a status code, or a fixed
operational role string. NEVER a raw request path, query string, case id,
user id, file name, or payload content. The middleware enforces the template
fallback ("unmatched") precisely so identifiers can never leak into labels.
"""

from time import perf_counter as _perf_counter
from typing import Dict

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response as StarletteResponse

# Single process-wide registry (the default registry) — rendered by
# /internal/metrics. Multi-process mode is intentionally NOT used: the engine
# is a single uvicorn process (see Dockerfile CMD).
REGISTRY = CollectorRegistry(auto_describe=True)

# --- HTTP request observability (middleware-updated) -----------------------
# path label = FastAPI route TEMPLATE, never the raw URL.
HTTP_RESPONSES_TOTAL = Counter(
    "burhan_http_responses_total",
    "HTTP responses by method, route template and status code.",
    labelnames=("method", "path", "code"),
    registry=REGISTRY,
)
HTTP_REQUEST_DURATION = Histogram(
    "burhan_http_request_duration_seconds",
    "Request duration by route template (drives case-query p95).",
    labelnames=("path",),
    registry=REGISTRY,
)
CASE_QUERY_PATHS = frozenset(
    {
        "/api/v2/cases",
        "/api/v2/cases/{case_id}",
        "/api/v2/cases/{case_id}/transition",
    }
)
# Evidence upload route templates (rejection-rate source: 4xx on these).
UPLOAD_PATHS = frozenset(
    {
        "/api/v2/evidence/upload",
        "/api/v2/cases/{case_id}/evidence",
    }
)
UPLOAD_REJECTIONS_TOTAL = Counter(
    "burhan_upload_rejections_total",
    "Evidence upload requests rejected (4xx) by route template and code.",
    labelnames=("path", "code"),
    registry=REGISTRY,
)

# --- Readiness observability (R15 /ready — read-only mirror) ---------------
READINESS_LATENCY = Histogram(
    "burhan_readiness_latency_seconds",
    "Duration of the /ready subsystem check computation.",
    registry=REGISTRY,
)
READINESS_FAILURES_TOTAL = Counter(
    "burhan_readiness_failures_total",
    "Readiness checks answered 503 (drives the repeated-503 alert).",
    registry=REGISTRY,
)

# --- EVM RPC observability --------------------------------------------------
RPC_ERRORS_TOTAL = Counter(
    "burhan_rpc_errors_total",
    "EVM RPC failures by operation kind (listener/probe/verify).",
    labelnames=("op",),
    registry=REGISTRY,
)
# Set by the /internal/metrics scrape-time eth_blockNumber probe (real call).
RPC_PROBE_SUCCESS = Gauge(
    "burhan_rpc_probe_success",
    "1 when the scrape-time eth_blockNumber probe succeeded.",
    registry=REGISTRY,
)
RPC_PROBE_LATENCY = Gauge(
    "burhan_rpc_probe_latency_seconds",
    "Latency of the scrape-time eth_blockNumber probe.",
    registry=REGISTRY,
)
EVM_BLOCK_NUMBER = Gauge(
    "burhan_evm_block_number",
    "Chain head observed by the scrape-time probe.",
    registry=REGISTRY,
)

# --- DB-sourced gauges (updated at scrape time by the metrics route) -------
WORKER_HEARTBEAT_AGE = Gauge(
    "burhan_worker_heartbeat_age_seconds",
    "Age of the freshest heartbeat per (institution, worker role); SQL-clock "
    "computed from worker_heartbeats (the R08 source of truth).",
    labelnames=("institution", "role"),
    registry=REGISTRY,
)
OUTBOX_OLDEST_AGE = Gauge(
    "burhan_outbox_oldest_pending_age_seconds",
    "Age of the oldest outbox event still PENDING or PROCESSING "
    "(SQL-clock); the delivery pipeline the anchor worker drains.",
    labelnames=("institution",),
    registry=REGISTRY,
)
OUTBOX_EVENTS = Gauge(
    "burhan_outbox_events",
    "Outbox events per delivery status (R08 states).",
    labelnames=("institution", "status"),
    registry=REGISTRY,
)
CHAIN_SUBMISSIONS = Gauge(
    "burhan_chain_submissions",
    "Chain submissions per status (SIGNED/BROADCAST/CONFIRMED/...).",
    labelnames=("institution", "status"),
    registry=REGISTRY,
)
CHAIN_SUBMISSIONS_AWAITING = Gauge(
    "burhan_chain_submissions_awaiting_confirmation",
    "Submissions not yet CONFIRMED (SIGNED + BROADCAST) — confirmation depth.",
    labelnames=("institution",),
    registry=REGISTRY,
)
METRICS_DB_UP = Gauge(
    "burhan_metrics_db_up",
    "1 when the metrics route could read its DB sources with tenant context.",
    registry=REGISTRY,
)

# Route templates counted as readiness probes (both registered prefixes).
READY_PATHS = frozenset(
    {
        "/health/ready",
        "/api/v2/health/ready",
        "/health/startup",
        "/api/v2/health/startup",
    }
)


def render_metrics() -> bytes:
    """Prometheus text exposition of the process registry."""
    return generate_latest(REGISTRY)


def route_template(request_scope: Dict) -> str:
    """Route TEMPLATE for a request scope — the no-PII label contract.

    Returns the matched route's path template (e.g. /api/v2/cases/{case_id})
    or "unmatched" (404/405 before routing). Raw URLs, query strings and real
    identifiers are never returned.
    """
    route = request_scope.get("route")
    template = getattr(route, "path", None)
    if not template:
        return "unmatched"
    return str(template)


class ObservabilityMiddleware(BaseHTTPMiddleware):
    """Counts every HTTP response with NO-PII labels (route templates only)
    and feeds the readiness/case-query/upload-rejection golden metrics.

    The route template is read AFTER call_next: FastAPI stores the matched
    route on request.scope during routing, so rejected/unmatched requests
    land on the constant "unmatched" label — raw identifiers never reach a
    label. Unhandled exceptions are counted as 500 and re-raised.
    """

    async def dispatch(self, request: Request, call_next) -> StarletteResponse:
        started = _perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            self._observe(request.scope, "500", _perf_counter() - started)
            raise
        self._observe(request.scope, str(response.status_code),
                      _perf_counter() - started)
        return response

    @staticmethod
    def _observe(scope: Dict, code: str, elapsed: float) -> None:
        method = scope.get("method", "-")
        template = route_template(scope)
        HTTP_RESPONSES_TOTAL.labels(
            method=method, path=template, code=code
        ).inc()
        HTTP_REQUEST_DURATION.labels(path=template).observe(elapsed)

        if template in READY_PATHS:
            READINESS_LATENCY.observe(elapsed)
            if code == "503":
                READINESS_FAILURES_TOTAL.inc()
        if template in UPLOAD_PATHS and 400 <= int(code) < 500:
            UPLOAD_REJECTIONS_TOTAL.labels(path=template, code=code).inc()
