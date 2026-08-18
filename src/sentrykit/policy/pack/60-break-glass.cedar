// Emergency access: an entitlement, a flag *and* a justification -- never a flag alone.
//
// Phase 5 research measured the obvious draft, a permit conditioned on `context.break_glass`
// only, and found that it authorizes literally anyone: the flag is caller-supplied, and a
// Cedar permit needs no base entitlement to fire. So the resource declares an
// `emergency_role`, the principal must be in it, and the context must carry a non-empty
// justification.
//
// The forbid half is what makes an emergency-only resource emergency-only: it fires whenever
// the flag is absent, and forbid beats every other permit in the pack. The permit carries a
// mandatory obligation, so a call that proceeds this way cannot proceed quietly.
@id("emergency-resource-forbidden-without-flag")
forbid (principal, action, resource)
when
{
  resource has emergency_only &&
  resource.emergency_only &&
  !(context has break_glass && context.break_glass)
};

@id("break-the-glass")
@obligations("notify:secops,record:justification")
permit (principal, action, resource)
when
{
  resource has emergency_only &&
  resource.emergency_only &&
  resource has emergency_role &&
  principal in resource.emergency_role &&
  context has break_glass &&
  context.break_glass &&
  context has justification &&
  context.justification != ""
};
