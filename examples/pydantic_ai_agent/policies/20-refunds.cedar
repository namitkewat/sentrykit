// Reviewed policy logic for refunds. The two forbids here are the multi-argument cases: one
// weighs a proposed argument against the principal, the other weighs two proposed arguments
// against each other. Both are Cedar evaluating the whole request at once -- sentrykit needs
// no extra syntax for either, and no per-argument rule could express either one.

// The entitlement, stated plainly and with no condition on it. Keeping the permit
// unconditional is what lets an agent see this tool at all: a manifest probe proposes no
// arguments, so a permit that read `context.args` would evaluate to false there and the tool
// would be hidden from everybody, including the people who may use it.
@id("support-may-issue-refunds")
permit (
  principal in Role::"support",
  action == Action::"refunds.issue",
  resource == Tool::"refunds"
);

// The desk limit, as an exception to the line above. Cedar's forbid always wins, so the
// exception is expressed without editing the permit. This one reads a proposed argument
// TOGETHER WITH the principal -- one decision over the whole request, which is why no
// per-argument rule could stand in for it.
@id("refunds-above-the-desk-limit-need-an-admin")
forbid (
  principal,
  action == Action::"refunds.issue",
  resource == Tool::"refunds"
) when {
  context.args has amount && context.args.amount > 1000 && !(principal in Role::"admin")
};

// The other multi-argument shape: two arguments, each individually fine, refused purely for
// their combination -- a big refund outside the home region. amount=100 in uk is allowed;
// amount=750 in uk is not, and neither value is out of bounds on its own.
@id("no-large-cross-region-refunds")
forbid (
  principal,
  action == Action::"refunds.issue",
  resource == Tool::"refunds"
) when {
  context.args has region && context.args has amount &&
  context.args.region != "eu" && context.args.amount > 200
};

@id("admins-may-approve-refunds")
permit (
  principal in Role::"admin",
  action == Action::"refunds.approve",
  resource == Tool::"refunds"
);
