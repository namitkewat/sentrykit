// Reviewed policy logic for the orders desk. This file is code: it lives in git, it is read in
// review, and nothing at runtime rewrites it. Who holds which role, and which values each person
// may pass, are data in the grant store -- see policy.py.
//
// Read this file as the answer to one question: what is true for EVERYBODY, whatever any grant
// says? A grant can narrow what is written here and can never widen it, so a reviewer who has
// read these nine blocks knows the outer edge of what the desk can be asked to do -- without
// having to audit a store that an admin surface mutates.
//
// Nothing below names a principal. Two of the permits are reached by both people in the suite,
// and the suite's outcomes still differ, because what differs is their grant data rather than
// their entitlement.

@id("support-may-search")
// @constraints is a CEDAR POLICY ANNOTATION, not a Python decorator. It declares an argument
// CEILING: the most that ANYBODY reaching this permit may pass, stated in the reviewed file
// rather than in a store an admin surface can edit. It INTERSECTS with the caller's own grant
// and can only narrow -- alice's grant already caps limit at 50, so this 100 never binds for her.
//
// A value above the ceiling is REJECTED and the principal's own default refills the gap. It does
// not become 100. A ceiling may set allow, deny, pattern, minimum, maximum and required, and
// deliberately not default: the reviewed file states the bound, and which value fills the gap
// afterwards is the principal's own data.
@constraints("{\"limit\": {\"maximum\": 100}}")
permit (
  principal in Role::"support",
  action == Action::"desk.search",
  resource == Tool::"orders"
);

// Reading a customer's words. Permitted, unconditionally, and worth being deliberate about: the
// text that comes back was typed by somebody outside the desk, and a caller that hands it to a
// model is handing a stranger's sentences to something that acts on sentences. Nothing in this
// file can change that, and nothing in it needs to -- what a model is told is not an action, so
// it is not where authorization belongs. The gate is on whatever the model proposes NEXT, which
// is every other policy here.
@id("support-may-read-tickets")
permit (
  principal in Role::"support",
  action == Action::"desk.ticket",
  resource == Tool::"tickets"
);

@id("support-may-list-tenant-orders")
// The reviewed file stating, in one line, that nobody reaches another tenant. Written here rather
// than as a grant on each principal for the obvious reason: a rule that has to be repeated per
// person is a rule that will eventually be missed for one of them, and this is the rule where
// missing it means serving one customer's orders to another.
//
// Follow this ceiling into the two outcomes it produces, because they differ by exactly one piece
// of grant data. A proposal of somebody else's tenant is rejected for both people in the suite.
// alice holds a `tenant_id` default, so her gap is refilled and her call continues against her
// own tenant. bob holds no `tenant_id` grant at all, so there is nothing to refill with and his
// call is refused. One reviewed line; narrow-and-continue for one caller, a refusal for the
// other, and neither outcome required a policy that knew their names.
@constraints("{\"tenant_id\": {\"allow\": [\"acme\"]}}")
permit (
  principal in Role::"support",
  action == Action::"desk.tenants",
  resource == Tool::"orders"
);

// The reporting read. No ceiling on it, and not because none was wanted: the figure worth
// bounding in that call is one the body computes rather than one the caller proposes, and an
// argument ceiling bounds arguments. See `region_report` in desk_tools.py, which says plainly
// what it hands back and why no line in this file reaches it.
@id("support-may-report")
permit (
  principal in Role::"support",
  action == Action::"desk.report",
  resource == Tool::"orders"
);

// The destructive call, permitted at the role level and then bounded twice: by the forbid below,
// for everybody, and by each principal's own deny-set in the grant store. Keeping the permit
// unconditional is also what lets an agent be offered this tool at all -- a manifest probe
// proposes no arguments, so a permit that read `context.args` would evaluate to false there and
// the tool would be hidden from everybody, including the people who may use it.
@id("support-may-cancel-open-orders")
permit (
  principal in Role::"support",
  action == Action::"desk.cancel",
  resource == Tool::"orders"
);

// The widest possible proposal, refused for everybody. `all` is the desk's own desk-wide form of
// this call -- one argument that takes every region's open orders at once -- which is exactly why
// it is worth a line of reviewed text rather than a bound in a store. Cedar sees the caller's RAW
// arguments, before any per-principal filtering, so this reads what was actually proposed rather
// than what a grant would have left of it.
//
// Two things make this a forbid rather than a deny-set in the store. It holds for every
// principal, including ones added later with no deny-set of their own; and a forbid DENIES, where
// a rejected argument narrows. There is no refill after this: the call does not proceed against
// some safer region, it does not happen. For a call that cancels orders, the difference between
// "continued with a narrower value" and "did not happen" is the only difference that matters.
@id("no-desk-wide-cancels")
forbid (
  principal,
  action == Action::"desk.cancel",
  resource == Tool::"orders"
) when { context.args has region && context.args.region == "all" };
