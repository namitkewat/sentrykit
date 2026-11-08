// Order-side policy logic for the governed MCP server.
//
// This file is *logic*, and it lives in git because it is meant to be read in a review. Who
// holds `Role::"support"`, which regions alice may search and what her limit defaults to are
// *data*, seeded in policy.py and mutable by an admin surface at runtime. Nothing at runtime
// rewrites this file.
//
// The numeric filename prefix only orders the files as Cedar numbers them. Any name ending
// in `.cedar` is picked up by the FilesystemPolicySource that loads this directory.

// The role gate for searching, plus the argument ceiling that bounds it for EVERYBODY.
//
// `@constraints` is a **Cedar policy annotation** -- not a Python decorator, and not
// something the library invented syntax for. Cedar carries annotations verbatim and does not
// type-check their values, so sentrykit parses this one at load time: a malformed ceiling
// fails at wiring rather than quietly enforcing nothing. The value is compact JSON mapping an
// argument name to the rules bounding it, in the same vocabulary a grant uses.
//
// It **intersects** with the calling principal's own grant, and it can only narrow. Alice's
// grant caps `limit` at 50, so 50 is what applies to her and this line never bites. Dana's
// grant sets no maximum at all, so this reviewed 100 is her only bound -- and a value above it
// is REJECTED, then refilled from her own default of 25. The refill is her default, never this
// number: reject-and-refill, not a clamp.
@id("support-may-search")
@constraints("{\"limit\": {\"maximum\": 100}}")
permit (
  principal in Role::"support",
  action == Action::"orders.search",
  resource == Tool::"orders"
);

// `summarize_orders` is protected but is NOT registered as a tool. No model can propose it;
// it is reached only from inside another protected callable, and it is decided on its own
// terms all the same.
@id("support-may-summarize")
permit (
  principal in Role::"support",
  action == Action::"orders.summarize",
  resource == Tool::"orders"
);

// The tool that calls the one above. Two protected callables in one dispatch means two
// decisions and two audit records.
@id("support-may-brief")
permit (
  principal in Role::"support",
  action == Action::"orders.brief",
  resource == Tool::"orders"
);

@id("auditor-may-export")
permit (
  principal in Role::"auditor",
  action == Action::"orders.export",
  resource == Tool::"orders"
);

// A `forbid` that reads the caller's proposed argument. Cedar sees the RAW proposal -- what
// the caller wrote, before any per-principal filtering -- so `fmt="pdf"` is refused at the
// gate for everyone, including the auditor who may otherwise export. A forbid always beats a
// permit, which is how an exception is expressed without editing the permit above.
@id("no-pdf-exports")
forbid (
  principal,
  action == Action::"orders.export",
  resource == Tool::"orders"
) when { context.args has fmt && context.args.fmt == "pdf" };

// The relationship policy. It names ONLY the far end of the chain: no team, no division, no
// `Order::"ord-0003"`. Cedar walks the entity graph to connect them.
@id("project-members-may-read-project-orders")
permit (
  principal in Project::"orders-eu",
  action == Action::"orders.read",
  resource in Project::"orders-eu"
);

// The bare-`@protect` callable. sentrykit derived this action id from the callable's import
// path, which is why it reads like one -- substitute your own app's module path. An explicit
// `action=` is what you want as soon as the policy outlives the module layout, because moving
// or renaming the function silently changes the id this line has to match.
@id("anyone-signed-in-may-see-desk-status")
permit (
  principal,
  action == Action::"examples.fastmcp_server.service.desk_status",
  resource
);
