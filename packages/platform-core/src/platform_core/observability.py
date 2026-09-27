"""OpenTelemetry setup (traces, metrics) and the platform's named instruments."""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

log = logging.getLogger(__name__)
_configured = False


def configure_telemetry(service_name: str, namespace: str, endpoint: str | None,
                        environment: str) -> None:
    global _configured
    if _configured:
        return
    resource = Resource.create({
        "service.name": service_name,
        "service.namespace": namespace,
        "deployment.environment.name": environment,
    })
    tracer_provider = TracerProvider(resource=resource)
    readers = []
    if endpoint:
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        readers.append(PeriodicExportingMetricReader(OTLPMetricExporter(endpoint=endpoint),
                                                     export_interval_millis=15_000))
    trace.set_tracer_provider(tracer_provider)
    metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=readers))
    _configured = True


class Instruments:
    """Named metrics. Attribute values must never contain PII or secrets."""

    def __init__(self) -> None:
        m = metrics.get_meter("samiir_fatma")
        self.http_requests = m.create_counter("http.server.requests")
        self.tool_calls = m.create_counter("agent.tool.calls", description="tool invocations")
        self.tool_failures = m.create_counter("agent.tool.failures")
        self.tool_denials = m.create_counter("agent.tool.denials")
        self.tool_latency = m.create_histogram("agent.tool.latency", unit="ms")
        self.llm_latency = m.create_histogram("agent.llm.latency", unit="ms")
        self.llm_tokens = m.create_counter("agent.llm.tokens")
        self.agent_runs = m.create_counter("agent.runs")
        self.guardrail_trips = m.create_counter("agent.guardrail.trips")
        self.scan_jobs = m.create_counter("scanner.jobs")
        self.scan_duration = m.create_histogram("scanner.job.duration", unit="s")
        self.findings = m.create_counter("scanner.findings")
        self.crm_activities = m.create_counter("crm.activities")
        self.appointments = m.create_counter("scheduling.appointments")
        self.notifications = m.create_counter("notifications.sent")
        self.security_events = m.create_counter("security.events.ingested")
        self.security_events_rejected = m.create_counter("security.events.rejected")
        self.incidents = m.create_counter("security.incidents")
        self.webhooks = m.create_counter("webhooks.received")
        self.audit_writes = m.create_counter("audit.writes")


_instruments: Instruments | None = None


def instruments() -> Instruments:
    global _instruments
    if _instruments is None:
        _instruments = Instruments()
    return _instruments


def tracer(name: str = "samiir_fatma") -> trace.Tracer:
    return trace.get_tracer(name)


@contextmanager
def timed(histogram: Any, attributes: dict[str, str] | None = None) -> Iterator[None]:
    start = time.perf_counter()
    try:
        yield
    finally:
        histogram.record((time.perf_counter() - start) * 1000, attributes or {})


def current_trace_id() -> str | None:
    ctx = trace.get_current_span().get_span_context()
    return format(ctx.trace_id, "032x") if ctx.is_valid else None
