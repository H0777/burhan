"""Internal routes (H07): infrastructure-facing endpoints, no auth, no PII.

These routes live OUTSIDE /api versioning: they serve the compose-internal
network (Prometheus) only — the staging engine publishes no host port, so
they are not reachable from the host or through the nginx frontend proxy.
"""
