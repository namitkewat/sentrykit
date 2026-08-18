// Membership of a team, project or tenant, resolved through Cedar's parent closure.
//
// The resource names the group it belongs to; a principal reaches it through however many
// hops its own edges take. A member of `Group::"eu-west"` therefore satisfies a resource
// declaring `Group::"eu"` with no policy per level -- which is the multi-hop relationship
// resolution sentrykit exists to offload.
@id("group-membership")
permit (principal, action, resource)
when { resource has group && principal in resource.group };
