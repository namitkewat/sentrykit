// Refunds desk -- reviewed policy logic.
//
// Both rules below decide on the *relationship between two arguments*, which is worth
// reading twice: Cedar evaluates the whole request at once, so a rule about `amount` and
// `region` together needs no new syntax and no second decision point. sentrykit hands
// Cedar the proposed arguments and Cedar answers about all of them.

// The desk limit, with the admin branch folded into the same condition rather than written
// as a second policy. `principal in Role::"admin"` reads through the parent edge the grant
// store gives an admin, so one condition covers both populations.
//
// A `when` clause that comes out false does not produce a named refusal: no policy was
// determining, so the request falls through to Cedar's default deny and
// `determining_policies` is empty. Alice at 5000 is refused with nothing named.
@id("refunds-within-desk-limits")
permit (
  principal in Role::"support",
  action == Action::"refunds.issue",
  resource == Tool::"refunds"
) when {
  context.args has amount && (context.args.amount <= 1000 || principal in Role::"admin")
};

// Neither argument is out of bounds on its own -- a 750 refund is fine, and a `uk` refund is
// fine -- and the combination is refused. This is the shape that is painful to express as
// per-argument validation and trivial to express as one Cedar condition.
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
