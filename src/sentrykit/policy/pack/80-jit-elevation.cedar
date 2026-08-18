// Just-in-time elevation: a role held for a window, and only for that window.
//
// The elevation is two attributes on the principal -- which role, and until when -- so
// granting it is a store write rather than a policy change. The permit matches the elevated
// role against what the resource requires, which keeps elevation from becoming a blanket
// escalation: holding an elevation to one role says nothing about a resource that requires
// another.
//
// The forbid closes the window from the other side. Without it a lapsed elevation would
// merely stop matching this permit, leaving every other permit the principal has intact --
// which is right for a role they still hold and wrong for one that has just run out.

@id("jit-elevation")
@obligations("notify:secops")
permit (principal, action, resource)
when {
  principal has elevation_role &&
  principal has elevation_until &&
  context has now &&
  context.now <= principal.elevation_until &&
  resource has required_role &&
  principal.elevation_role == resource.required_role
};

@id("jit-elevation-expired-forbidden")
forbid (principal, action, resource)
when {
  principal has elevation_until &&
  context has now &&
  context.now > principal.elevation_until
};
