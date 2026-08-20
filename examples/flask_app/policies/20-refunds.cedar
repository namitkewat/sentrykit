// Refunds desk -- reviewed policy logic.
//
// Two of the rules below decide on more than the principal/action/resource triple, and that is
// worth reading twice: Cedar evaluates the whole request at once, so a rule about `amount` and
// the principal together -- or about `amount` and `region` together -- needs no new syntax and
// no second decision point. sentrykit hands Cedar the proposed arguments and Cedar answers
// about all of them.

// The gate, stated unconditionally: support issues refunds. Nothing here reads an argument, so
// this permit is reachable by a probe that proposes none. Folding the desk limit into a `when`
// on it would make the permit conditional on `context.args has amount`, and a caller who has
// proposed nothing yet -- an agent asking which tools it may attempt -- would be told the call
// would be refused. Permit broadly here; forbid narrowly below.
@id("support-may-issue-refunds")
permit (
  principal in Role::"support",
  action == Action::"refunds.issue",
  resource == Tool::"refunds"
);

// The desk limit, as an exception rather than as a condition on the permit: one argument
// decided TOGETHER WITH the principal. `principal in Role::"admin"` reads through the parent
// edge the grant store gives an admin, so one rule covers both populations -- support is
// bounded at 1000 and an admin is not bounded here at all.
//
// A forbid beats every permit, and it names itself: alice at 5000 is refused by this policy
// and `determining_policies` says so.
@id("refunds-above-the-desk-limit-need-an-admin")
forbid (
  principal,
  action == Action::"refunds.issue",
  resource == Tool::"refunds"
) when {
  context.args has amount && context.args.amount > 1000 && !(principal in Role::"admin")
};

// The other multi-argument rule, and this one reads nothing but the arguments. Neither is out
// of bounds on its own -- a 750 refund is fine, and a `uk` refund is fine -- and the pair is
// refused. This is the shape that is painful to express as per-argument validation and trivial
// to express as one Cedar condition.
@id("no-large-cross-region-refunds")
forbid (
  principal,
  action == Action::"refunds.issue",
  resource == Tool::"refunds"
) when {
  context.args has region && context.args has amount &&
  context.args.region != "eu" && context.args.amount > 200
};

// The admin action. Nobody holds `admin` in policy; the grant store says who does, and this
// file never changes when that answer does.
@id("admins-may-approve-refunds")
permit (
  principal in Role::"admin",
  action == Action::"refunds.approve",
  resource == Tool::"refunds"
);
