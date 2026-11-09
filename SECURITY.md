# Security policy

## Reporting a vulnerability

Report it privately through GitHub: **Security → Report a vulnerability** on this repository
opens a private thread with the maintainer, keeps the report together with the fix, and can
become a published advisory once a release carries that fix. If you would rather not go
through GitHub, email **namitkewat@gmail.com** with `sentrykit security` in the subject.
Either way, please include:

- what an attacker can do that they should not be able to do;
- the smallest reproduction you have — a policy set, a grant, and a call is usually enough;
- the sentrykit version, the Python version, and which integration (if any) is in play.

Please keep it out of the public issue tracker until there is a fix, and give a reasonable
window for one before disclosing. You will get an acknowledgement, and an honest answer about
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
protected callable and refuses the side effect *before* it happens — and, for a call it does
permit, decides which arguments that call may carry. It leads with the arguments, because
that is the layer sentrykit adds to the engine underneath it.

- **The arguments.** A caller — a browser, a script, or a language model — *proposes*
  arguments. Constraints resolved per principal and per action — allow-sets, deny-sets,
  patterns, numeric bounds — decide which of them survive, and an argument a principal may not
  pass does not reach the function body. A value above what the principal may have is
  **narrowed** rather than refused: it is rejected, and the defaults the principal's grants
  hold fill the gap — as they do for arguments the caller omitted. A value is never trimmed to
  the nearest one the principal may have, and where a grant holds no default the argument is
  dropped from what sentrykit passes. A default is itself checked against the constraint that
  governs it and withheld if it fails, so omitting an argument is not a way around the rule on
  it — **and that includes the callable's own default.** Dropping a governed argument leaves a
  slot Python would fill from the signature, so that value answers to the same constraint as
  any other default: if it satisfies the rule the call proceeds on it and says so, and if it
  does not the call is refused with `SignatureDefaultRejected`. Otherwise a bound could be
  exceeded *upward* — a caller refused a value above a ceiling would get the signature's
  number instead, which can be larger than the one they asked for. And a
  constraint no value could satisfy is refused when a grant store writes it — hand-editing a
  store's file bypasses that check — rather than discovered at the next call, where it would
  refuse everything. Two limits are worth stating plainly. The first is `arg_handling`:
  narrowing is what the default `lenient` setting does, and `strict` raises
  `ArgumentRejected` on the first rejected argument instead. The second is that narrowing
  *refines* a proposal, it does not replace one — if **every** argument the caller supplied was
  rejected, the call is refused with `NoValidArguments` rather than completed from defaults,
  because completing it would answer a question nobody asked.
- **A bound the admin surface cannot widen.** A reviewed `.cedar` file can declare an argument
  ceiling on a `permit`: what *anybody* may pass for that action. Ceilings and the grants held
  in the store **intersect**, so the file states the maximum and can only narrow — a mistake in
  a grant cannot raise a limit above it. Ceilings live in text that git reviews and that the
  audited `policy_set_hash` already covers, and because a failed evaluation reports no
  determining policies it reports no ceilings, so a governor whose policy set declares any
  ceiling refuses an engine failure under either fail mode rather than proceeding unbounded.
- **The call itself.** No principal, no matching policy, or an unavailable audit sink under a
  strict configuration all produce a denial. Default-deny is Cedar's model and it is ours; a
  gap in your policy set is a refusal, never an accidental permit.
- **The shape of the request itself.** Cedar reserves record keys beginning with `__` for the
  escape forms that promote a plain record into a typed entity reference. Supplied data
  carrying such a key is refused before the policy set is consulted, under either fail mode,
  so a `dict`-valued argument cannot promote itself into an entity of the caller's choosing.
  That closes the *spelling* and nothing more: a parameter your own signature annotates as an
  entity reference is still a caller-chosen entity, type included — the boundary listed below.
- **What an agent is shown.** On the agent side the tool manifest is filtered per principal: a
  tool is hidden from a caller exactly when invoking it would be refused. Hiding is a usability
  affordance rather than a control — the dispatch path re-runs the identical decision, so a
  client that skips the manifest is refused just the same.
- **Nested authorization relationships.** User → team → project → resource, delegation chains,
  on-behalf-of, expiry, break-the-glass and separation-of-duties are resolved deterministically
  by Cedar's entity hierarchy, never inferred by a model and never scattered across `if`
  statements, which means they can be reviewed, replayed and reasoned about. That is Cedar's
  strength and sentrykit inherits it; it composes with everything above, because the permit that
  resolves a chain is also the permit that can carry a ceiling.
- **The record.** Every decision and every administrative mutation is written to an append-only
  sink as a hash-chained record carrying the principal's effective attributes, the proposed and
  processed arguments, the determining policies and a hash of the exact policy set. Sensitive
  values are masked *before* the write, so the immutable store never holds the raw value and no
  read-time redaction can be forgotten or bypassed.

## Inherited assurance, and where it stops

The gate is Cedar's decision, so it carries whatever assurance Cedar's engine carries. Cedar's
authorization semantics are captured in a formal model, safety properties of the evaluator and
the validator are proved against that model, and the Rust implementation this library calls is
checked against it by large-scale differential testing. Cedar's own documentation states the
scope of that work, and it is the right place to read it: the claim is about how the engine
reaches a decision.

sentrykit makes **no** such claim for its own layer. Argument filtering, narrowing, default
injection, constraint intersection, masking and the hash chain are ordinary Python, backed by
tests and review and by nothing stronger. "Built on a formally verified engine" is a fact about
Cedar rather than a property of this library, and anyone assessing risk should weigh the two
layers separately.

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
- **It does not decide what your own signatures mean.** A parameter you annotate as
  `EntityRef` says the caller names an entity, and every integration validates their JSON
  against that annotation before the decorator runs — so the caller chooses the entity's
  **type** as well as its id. Cedar's `in` is reflexive, which makes
  `!(context.args.region in Group::"approved")` satisfiable by passing the approved group
  itself as the region. Pin the type with Cedar's `is` operator, bound the argument with a
  constraint or a ceiling, or declare `context.args` in a Cedar schema — all three close it,
  and the docs say so where the annotation is described. sentrykit cannot infer which of your
  parameters were meant to be caller-chosen.
- **It does not check that a ceiling names an argument you actually have.** `sentrykit policy
  validate` reads a directory of `.cedar` files and never imports your application, so there is
  no signature to compare against: a ceiling on `"limt"` parses, loads and bounds nothing, and
  nothing raises. Every other property of a ceiling is checked at load, which makes this the one
  way a declared bound can be silently absent. Read a ceiling against the signature it names,
  and cover it with a test that proposes a value the ceiling should reject.
- **It does not remember what an earlier call was narrowed to.** A call narrowed to
  `region="eu"` may hand back an export id, a job handle or a cursor, and sentrykit does not
  track, sign or scope that string. The next call presenting it is decided on its own
  principal and its own arguments, so a caller who could never have asked for the EU book
  directly can be served it by presenting a handle somebody else was given. The handle is
  not the hole — the narrowing lives on your row and not in the request, and nothing that
  only sees the request can enforce it. Resolve the handle before the gate and pass what you
  found as an ordinary argument (`fetch(job_id, region=lookup(job_id).region)`); the
  principal's own constraints then decide it, the envelope reports it and the record pins it.
  Then check in the body that the handle and the argument agree, because policy allowing a
  region the caller *is* entitled to says nothing about whether this job is theirs. Both
  halves are yours, and only the first is authorization. `examples/scenarios/` runs the
  sequence all three ways, including the one it does not win.
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
4. Put a bound that must not be raised by mistake in an **argument ceiling** in a reviewed
   `.cedar` file, not only in a grant. A grant is data the admin API can rewrite; a ceiling
   needs a commit and a deploy, and it can only narrow what a grant allows.
5. If a protected callable takes an entity from the caller, **pin its type in policy**.
   `context.args.region is Region && context.args.region in Group::"approved"` is the fix;
   bounding the argument with a constraint or a ceiling, or declaring `context.args` in a Cedar
   schema, closes it too. Cedar's `in` is reflexive, so an unpinned membership test is satisfied
   by passing the group itself.
6. Declare **`Sensitive`** on every argument that carries a secret, a token or personal data, so
   masking happens before the record is written.
7. Authenticate before you authorize, and make sure the context provider derives the principal
   from something the caller cannot set.
8. Treat the shipped policy pack as a **starting point**. It ships no permit for the
   administrative actions on purpose: you write that one, and reviewing it is the moment you
   decide who administers your grants.
