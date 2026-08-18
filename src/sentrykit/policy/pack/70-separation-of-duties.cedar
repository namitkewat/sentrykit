// Two duties that must not land on one person.
//
// The first half is static incompatibility: the resource declares the role that must *not*
// hold it, so "nobody in the audit role may touch settlement" is a resource attribute rather
// than a cross-product of policies.
//
// The second is the four-eyes rule, and it needs the approval action to be identifiable. The
// pack ships `Action::"approve"` in its entity graph precisely so a host can map its own
// actions into it -- `Action::"payments.approve" in Action::"approve"` -- and have this
// forbid apply without editing reviewed policy logic.
@id("sod-conflicting-role")
forbid (principal, action, resource)
when
{ resource has conflicting_role && principal in resource.conflicting_role };

@id("sod-same-actor-approval")
forbid (
  principal,
  action in Action::"approve",
  resource
)
when { resource has prepared_by && resource.prepared_by == principal };
