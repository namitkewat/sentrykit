# Security policy

## Reporting a vulnerability

Email **namitkewat@gmail.com** with `sentrykit security` in the subject. Please include:

- what an attacker can do that they should not be able to do;
- the smallest reproduction you have — a policy set, a grant, and a call is usually enough;
- the sentrykit version, the Python version, and which integration (if any) is in play.

Please report privately first rather than opening a public issue, and give a reasonable window
for a fix before disclosing. You will get an acknowledgement, and an honest answer about
whether the behaviour is a bug or a documented limitation — the second is a real outcome here,
because several things that *look* like holes are boundaries this library deliberately does not
cross. Those are listed below, and finding one of them documented is not a brush-off; it means
the defence you are looking for belongs in a different layer.

sentrykit is pre-1.0 and self-hosted: there is no service to patch on your behalf. A fix ships
as a release, and you upgrade.

## Supported versions

The latest `0.x` release. While the public API is pre-1.0 there is no long-term support branch;
security fixes go onto the newest release rather than being backported.

## What sentrykit defends

sentrykit is **pre-action authorization at the action layer**. It stands between a caller and a
protected callable and refuses the side effect *before* it happens.

- **The call itself.** No principal, no matching policy, or an unavailable audit sink under a
  strict configuration all produce a denial. Default-deny is Cedar's model and it is ours; a
  gap in your policy set is a refusal, never an accidental permit.
- **The arguments.** A caller — a browser, a script, or a language model — *proposes*
  arguments. Policy decides which of them survive, which are replaced by defaults, and whether
  the resulting call is well-formed. An argument a principal may not pass does not reach the
  function body.
- **Nested authorization relationships.** User → team → project → resource, delegation chains,
  on-behalf-of, expiry, break-the-glass and separation-of-duties are resolved deterministically
  by Cedar's entity hierarchy. They are never inferred by a model and never scattered across
  `if` statements, which means they can be reviewed, replayed and reasoned about.
- **What an agent is shown.** On the agent side the tool manifest is filtered per principal: a
  tool is hidden from a caller exactly when invoking it would be refused. Hiding is a usability
  affordance rather than a control — the dispatch path re-runs the identical decision, so a
  client that skips the manifest is refused just the same.
- **The record.** Every decision and every administrative mutation is written to an append-only
  sink as a hash-chained record carrying the principal's effective attributes, the proposed and
  processed arguments, the determining policies and a hash of the exact policy set. Sensitive
  values are masked *before* the write, so the immutable store never holds the raw value and no
  read-time redaction can be forgotten or bypassed.

## What sentrykit does not defend

Being explicit about this is the point of the section. Each item below is a deliberate boundary,
not a missing feature — and each one names the layer that does cover it.

- **It does not sandbox a tool body.** Once a call is authorized, the function runs with your
  process's full privileges. If a protected callable shells out, writes anywhere on disk, or
  holds a database connection that ignores the principal entirely, sentrykit has no view of any
  of it. Confinement is the job of the runtime — containers, seccomp, a least-privilege database
  role — and authorization does not substitute for it.
- **Without a durable WORM sink it detects tampering rather than preventing it.** The hash chain
  makes an edited or deleted record *visible*: `verify_chain` reports the first break. It cannot
  stop a writer with filesystem access from truncating the log, and a sufficiently determined
  attacker who controls the process can rewrite the whole chain from a chosen point. Real
  immutability comes from the storage layer — S3 Object Lock, an Iceberg table on
  versioned object storage, an append-only log service — behind the same `AuditSink` protocol.
  Until you wire one up, treat the chain as an integrity check, not as a guarantee.
- **It is not a content filter or an output validator.** It refuses the action, not the text.
  Prompt injection that persuades a model to *call* something is caught here — the policy
  refuses the call regardless of why the model proposed it — but nothing sentrykit does inspects
  a model's output for sensitive content, and nothing validates what a permitted call returns.
- **It does not authenticate.** `Principal` is whatever your context provider establishes at the
  boundary. sentrykit trusts it completely, because it has no way not to. A forged session, a
  spoofed MCP auth context or a service that establishes a principal from an unverified header
  produces perfectly-audited authorization of the wrong identity. Authentication is upstream and
  it is yours.
- **The trust boundary is the process, not the policy.** Anything running inside your
  application can import sentrykit and call `install()`, `configure()` or `set_governor()`.
  Policy protects your application's callers; it does not protect your application from its own
  code, from a compromised dependency, or from anyone who can edit the policy directory.
  Policies-as-code exists so that changing the rules requires a reviewed commit — that review is
  the control, and skipping it removes it.
- **It does not defend against denial of service.** Every call runs a Cedar evaluation and
  writes an audit record. A caller who can trigger protected calls at will can make you do both
  at their chosen rate. Rate limiting belongs at the edge.
- **Break-the-glass is auditable, not restrained.** An emergency grant requires an entitlement,
  an explicit flag *and* a written justification, and it discharges a mandatory obligation into
  the audit trail — so it cannot be used quietly. It does not stop an entitled principal from
  using it. That is the design: emergencies need an escape hatch, and the control is that the
  hatch is loud.

## Hardening checklist

If you are deploying sentrykit into something that matters:

1. Run **fail-closed** (`fail_mode="closed"`, the default) and leave it there. Fail-open means
   an engine or sink failure silently authorizes.
2. Point the audit sink at **durable, write-once storage**, and verify the chain on a schedule
   rather than only after an incident.
3. Keep policy logic in **git**, reviewed. Keep grants in a store the admin surface mutates —
   never let a runtime path rewrite reviewed policy text.
4. Declare **`Sensitive`** on every argument that carries a secret, a token or personal data, so
   masking happens before the record is written.
5. Authenticate before you authorize, and make sure the context provider derives the principal
   from something the caller cannot set.
6. Treat the shipped policy pack as a **starting point**. It ships no permit for the
   administrative actions on purpose: you write that one, and reviewing it is the moment you
   decide who administers your grants.
