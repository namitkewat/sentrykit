// An entitlement that stops on its own, at both ends.
//
// A grant store already drops expired grants when it materializes a principal, so this is
// the belt to that store's braces: a principal assembled by a host's own directory, or one
// carrying an entitlement window as a plain attribute, still stops being entitled at the
// declared moment. Expressed as a forbid so it beats every permit in the pack -- an expiry
// that could be out-voted is not an expiry.
@id("entitlement-expired-forbidden")
forbid (principal, action, resource)
when
{
  principal has entitlement_expires &&
  context has now &&
  context.now > principal.entitlement_expires
};

@id("entitlement-not-yet-valid-forbidden")
forbid (principal, action, resource)
when
{
  principal has entitlement_starts &&
  context has now &&
  context.now < principal.entitlement_starts
};
