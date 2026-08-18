// The owner of a thing may act on it.
//
// Equality, not `in`: ownership is not inherited. A team the owner belongs to does not
// become an owner, and handing ownership on is a separate grant rather than a side effect
// of a group edge.

@id("resource-owner")
permit (principal, action, resource)
when {
  resource has owner &&
  resource.owner == principal
};
