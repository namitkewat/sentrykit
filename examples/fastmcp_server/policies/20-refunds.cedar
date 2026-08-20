// Refund-side policy logic. Two of these four rules decide on MORE THAN the principal/action/
// resource triple -- one on an argument together with the principal, one on the relationship
// between two arguments -- which is Cedar evaluating the whole request: sentrykit needs no
// extra syntax for either shape, because the proposal reaches Cedar as `context.args`.

// The gate, and it is deliberately unconditional. Nothing here reads an argument, so this
// permit is reachable by a probe that proposes none -- which is exactly what `tools/list` is.
// Fold the desk limit into a `when` on this permit and it would depend on
// `context.args has amount`; a manifest probe carries no arguments, so the honest answer at
// manifest time would be "refused", and `issue_refund` would vanish from every manifest while
// still working perfectly well at dispatch. Permit broadly here, forbid narrowly below.
@id("support-may-issue-refunds")
permit (
  principal in Role::"support",
  action == Action::"refunds.issue",
  resource == Tool::"refunds"
);

// The desk limit, written as an exception rather than as a condition on the permit: an argument
// decided TOGETHER WITH the principal. A support user may issue up to 1000; an admin is not
// bounded here at all, because `principal in Role::"admin"` reads through the parent edge the
// grant store gives an admin. One rule covers both populations.
//
// A forbid beats every permit AND names itself, so a 5000-unit refund refused for alice reports
// `determining_policies == ["refunds-above-the-desk-limit-need-an-admin"]`. There is a policy id
// to go looking for, and this is it.
@id("refunds-above-the-desk-limit-need-an-admin")
forbid (
  principal,
  action == Action::"refunds.issue",
  resource == Tool::"refunds"
) when {
  context.args has amount && context.args.amount > 1000 && !(principal in Role::"admin")
};

// A rule about two arguments TOGETHER, and about nothing else. Neither `region="uk"` nor
// `amount=750` is out of bounds on its own -- alice's grant permits both -- and the combination
// is refused anyway. A forbid beats every permit, so this holds for admins too.
@id("no-large-cross-region-refunds")
forbid (
  principal,
  action == Action::"refunds.issue",
  resource == Tool::"refunds"
) when {
  context.args has region && context.args has amount &&
  context.args.region != "eu" && context.args.amount > 200
};

// `Role::"admin"` has `Role::"support"` as a parent in the entity graph, so an admin satisfies
// the support gate above by one edge instead of by a second grant on every admin. This policy
// is the part only an admin reaches.
@id("admins-may-approve-refunds")
permit (
  principal in Role::"admin",
  action == Action::"refunds.approve",
  resource == Tool::"refunds"
);
