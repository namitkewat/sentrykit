// Reviewed policy logic for the orders desk. This file is code: it lives in git, it is read
// in review, and nothing at runtime rewrites it. Who holds which role, and which values each
// person may pass, are data in the grant store -- see policy.py.
//
// The agent boundary changes nothing here. A model proposing a tool call produces the same
// Cedar request an HTTP route or a cron job would, so this file would work unaltered behind
// any of them.

@id("support-may-search")
// @constraints is a CEDAR POLICY ANNOTATION, not a Python decorator. It declares an argument
// CEILING: the most that ANYBODY reaching this permit may pass, stated in the reviewed file
// rather than in a store an admin surface can edit. It INTERSECTS with the caller's own grant
// and can only narrow -- alice's grant already caps limit at 50, so this 100 never binds for
// her; dana has no cap of her own, so this is the only bound she has.
//
// A value above the ceiling is REJECTED and the principal's own default refills the gap. It
// does not become 100. Watch dana propose 500 and run with 25.
@constraints("{\"limit\": {\"maximum\": 100}}")
permit (
  principal in Role::"support",
  action == Action::"orders.search",
  resource == Tool::"orders"
);

// Reached from inside brief_orders, which is a tool, by a callable that is not one. The gate
// is on the call, not on the tool registration.
@id("support-may-summarize")
permit (
  principal in Role::"support",
  action == Action::"orders.summarize",
  resource == Tool::"orders"
);

// The tool whose body calls a second protected callable. Two permits, two decisions.
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

// Cedar sees the caller's RAW proposed arguments, before per-principal filtering, so this
// reads what the model actually wrote. forbid always beats permit, which is how an exception
// is expressed without editing the permit above.
@id("no-pdf-exports")
forbid (
  principal,
  action == Action::"orders.export",
  resource == Tool::"orders"
) when { context.args has fmt && context.args.fmt == "pdf" };

// Multi-hop, resolved by Cedar rather than by an `if`. Neither side of this permit names a
// person: alice reaches Project::"orders-eu" through Team::"eu-support" and Division::"emea",
// and Order::"o-1" reaches it as a parent. bob's chain is the same length and lands in
// orders-us, so he is refused -- with no policy naming him either way.
@id("project-members-may-read-project-orders")
permit (
  principal in Project::"orders-eu",
  action == Action::"orders.read",
  resource in Project::"orders-eu"
);

// The bare-@protect callable. sentrykit derived this action id from the callable's import
// path, which is why it reads like one -- substitute your own app's module path. Moving or
// renaming the function changes the id, and therefore breaks this policy: pass an explicit
// action= as soon as the policy is expected to outlive the module layout.
@id("anyone-signed-in-may-see-desk-status")
permit (
  principal,
  action == Action::"examples.pydantic_ai_agent.service.desk_status",
  resource
);
