// Orders desk -- reviewed policy logic.
//
// This file is *code*. It is authored here, read in review, versioned in git, and never
// rewritten at runtime. The mutable half of authorization -- who holds which role, which
// regions a given person may search, what they get when they name nothing -- is grant
// *data*, seeded next door in `policy.py` and mutable by an admin surface.
//
// Cedar answers one question per policy: may this principal take this action on this
// resource? sentrykit puts a second layer above that answer -- which argument values the
// caller may pass -- and one half of that layer is declared right here, in the
// `@constraints` annotation below.

@id("support-may-search")
// `@constraints` is a **Cedar policy annotation, not a Python decorator**. Nothing imports
// it and nothing calls it; it is text on the policy, and sentrykit parses it when this
// directory is loaded.
//
// It declares an *argument ceiling*: the widest value ANY principal may pass for this
// action, stated in the same reviewed file as the permit it hangs on. It grants nobody
// anything. It **intersects** with whatever the grant store gives the caller, and an
// intersection can only narrow -- so this file states the maximum and a grant may tighten
// it, never loosen it. Alice's own grant caps `limit` at 50, so 50 is what applies to her;
// the 100 below never widens her.
//
// A value that breaches the ceiling is rejected, and the caller's own default is put in the
// gap so the call still proceeds. The value they end up with is *their default*, which has
// no relation to the number below. Dana asks for 500 here and runs with 25.
@constraints("{\"limit\": {\"maximum\": 100}}")
permit (
  principal in Role::"support",
  action == Action::"orders.search",
  resource == Tool::"orders"
);

// The gate is on the callable, not on the URL. `orders.summarize` is reached from a route
// that says nothing about authorization, and this policy still decides it.
@id("support-may-summarize")
permit (
  principal in Role::"support",
  action == Action::"orders.summarize",
  resource == Tool::"orders"
);

// A different role on a different action: the auditor may export and may not search.
@id("auditor-may-export")
permit (
  principal in Role::"auditor",
  action == Action::"orders.export",
  resource == Tool::"orders"
);

// A `forbid` that reads the caller's proposed arguments. Cedar sees them exactly as they
// were written, before sentrykit's argument layer has touched anything -- so this refuses
// the side effect rather than tidying it. A forbid beats every permit, which is how an
// exception is expressed without editing the permit above.
@id("no-pdf-exports")
forbid (
  principal,
  action == Action::"orders.export",
  resource == Tool::"orders"
) when { context.args has fmt && context.args.fmt == "pdf" };

// Relationship resolution, and the only policy here that mentions no role at all. Alice
// reaches `Project::"orders-eu"` through Team -> Division -> Project, and `Order::"o-1"`
// reaches it through one edge of its own; Cedar walks both chains. Bob's chain is the same
// length and ends at `Project::"orders-us"`, so the same call is refused for him with no
// second policy written and no `if` statement anywhere in the app.
@id("project-members-may-read-project-orders")
permit (
  principal in Project::"orders-eu",
  action == Action::"orders.read",
  resource in Project::"orders-eu"
);

// The action id sentrykit derives for a bare `@protect`, which is the callable's import
// path. Substitute your own module path when you copy this. `resource` is unconstrained
// because a bare `@protect` synthesizes one from the same path -- a callable with no
// natural resource still has to fit Cedar's principal/action/resource shape.
@id("anyone-signed-in-may-see-desk-status")
permit (
  principal,
  action == Action::"examples.fastapi_app.service.desk_status",
  resource
);
