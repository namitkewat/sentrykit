// Acting on behalf of someone else, within a scope that binds rather than adds.
//
// The delegated principal -- typically an agent -- arrives from the grant store already
// carrying its own edges: who delegated to it, which actions it may take, and when the
// delegation lapses. The caller must also *declare* the delegation in the context, so a
// delegated identity is never used silently.
//
// The two forbids are what make the scope a boundary. Without them a delegated agent whose
// scope excludes an action would still reach the plain RBAC permit and take it anyway,
// because a Cedar permit needs no other permit's agreement -- only the absence of a forbid.
@id("delegation-on-behalf-of")
@obligations("record:on_behalf_of")
permit (principal, action, resource)
when
{
  context has on_behalf_of &&
  principal has delegated_by &&
  principal.delegated_by == context.on_behalf_of &&
  principal has delegated_actions &&
  action in principal.delegated_actions &&
  context has now &&
  principal has delegation_expires &&
  context.now <= principal.delegation_expires &&
  resource has required_role &&
  principal in resource.required_role
};

@id("delegation-outside-scope-forbidden")
forbid (principal, action, resource)
when
{ principal has delegated_actions && !(action in principal.delegated_actions) };

@id("delegation-expired-forbidden")
forbid (principal, action, resource)
when
{
  principal has delegation_expires &&
  context has now &&
  context.now > principal.delegation_expires
};
