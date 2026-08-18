# Logging standards

## Two channels, never conflated
sentrykit has **two distinct output channels** with different purposes, audiences, and
guarantees. Keep them separate in code and in sinks.

1. **Operational logs** — for developers/operators debugging the library and the app.
   Standard `logging`, may be verbose, routed to stdout/aggregator. Ephemeral. **Never
   contains secrets or unmasked sensitive values.**
2. **The audit log** — for compliance. This is *not* `logging`: it is the `AuthzAuditRecord`
   stream written to an append-only, tamper-evident `AuditSink`, with values masked before
   the write. It is a first-class data product, not a side effect. Do not route audit records
   through the operational logger, and do not treat operational logs as an audit trail.

## Operational logging rules
- Use `logging.getLogger("sentrykit")` and child loggers per module
  (`sentrykit.engine`, `sentrykit.cedar`, …). **Never call `logging.basicConfig`** in library
  code — leave configuration to the host app.
- Prefer structured/JSON-friendly logging: emit key/value context (request id, action,
  decision, principal id) rather than interpolated prose. `structlog` is acceptable but
  optional and must not become a hard core dependency.
- Levels: `DEBUG` internal decision tracing; `INFO` significant lifecycle events; `WARNING`
  recoverable anomalies (e.g. lenient drop of an invalid arg); `ERROR` misconfiguration or
  sink failure. A *deny* is normal operation — log at `INFO`/`DEBUG`, not `ERROR`.
- Always attach the correlation/request id so operational logs and audit records can be
  cross-referenced by id (never by copying sensitive payloads into logs).
- **Redaction applies here too.** Sensitive argument values must be masked in operational
  logs using the same strategies as the audit path. When in doubt, log the arg *name* and
  whether it was accepted/rejected, not its value.

## Audit "logging" rules
- One record per decision and per admin mutation. Mask before write. Chain records. Pin
  `policy_set_hash` and per-policy provenance. Give break-the-glass, delegation, and
  expired-grant events their own clearly-typed records carrying justification/reviewer where
  applicable.
- If the configured sink is unavailable and `fail_mode = closed`, refuse the action rather
  than proceed unlogged ("can't prove it, don't do it"). Surface this as an `ERROR`
  operational log *and* deny.

## Never
- Never log passwords, tokens, API keys, full account identifiers, or raw PII in either
  channel. Never put sensitive data in log messages destined for third-party aggregators.
