// Role-based access, without the pack ever naming a role.
//
// A shipped policy cannot know that your roles are called `support` and `oncall`, so the
// *resource* declares which role it requires and the grant store supplies the principal's
// edge to it. `principal in resource.required_role` is transitive, so a role hierarchy --
// `Role::"lead" in Role::"support"` -- resolves in Cedar rather than in application code.
@id("rbac-required-role")
permit (principal, action, resource)
when { resource has required_role && principal in resource.required_role };
