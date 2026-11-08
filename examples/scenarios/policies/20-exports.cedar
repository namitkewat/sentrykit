// Reviewed policy logic for exports. Three permits, and all three are really about one thing: an
// export handle is a capability. The desk stores the region and the scope the job was created
// under, so the handle remembers its own narrowing -- and it remembers it in the desk, where an
// argument constraint cannot reach. Presenting the handle later is a call whose single argument
// says nothing about what it will return.
//
// That is the shape worth taking away from this file, because it is not specific to exports:
// report ids, saved searches, share links, cursor tokens and job handles all work this way. A
// layer that decides which arguments a caller may pass can only decide about what is IN the
// arguments. When the consequences of a call live behind an opaque id, the host has to bring them
// back out into an argument -- which is what the second and third permits below are for, and why
// two actions exist over one resource.

// Minting a handle. The region an export covers is an argument here, so it is something a grant
// can bound: alice's export grant allows `eu` and `uk` and refills with `eu`, and the job the
// desk records is stamped with whatever policy settled on rather than with what was proposed.
// Getting this permit's constraints right is therefore worth more than it looks -- every later
// fetch inherits the narrowing that was in force at this moment.
@id("support-may-export")
permit (
  principal in Role::"support",
  action == Action::"desk.export",
  resource == Tool::"exports"
);

// Redeeming a handle, by the single argument form. Minting and redeeming are separate
// entitlements on purpose: creating a narrowed extract is routine desk work, while reading back
// an extract somebody else created is an auditor's. Because `Role::"auditor"` has
// `Role::"support"` as a parent, an auditor satisfies both -- the hierarchy says an auditor can
// do everything support can and one thing more, rather than listing the overlap twice.
//
// Note what a constraint has to work with here. The only argument is the handle, so the only
// thing a grant can decide is the handle's SHAPE -- bob's `exp-[0-9]{4}` pattern, with no default,
// because no invented handle could be the right one. Which rows come back is decided by the job
// row, and no rule written in Cedar or in a grant store sees that row.
@id("auditor-may-fetch-exports")
permit (
  principal in Role::"auditor",
  action == Action::"desk.fetch",
  resource == Tool::"exports"
);

// The same read, with the narrowing brought back out into the open. This action takes the region
// the caller believes the handle covers, and the body answers nothing when the claim and the job
// disagree. One argument added, and the whole call becomes decidable: bob's grant allows `us` and
// nothing else, with no default, so a claim outside it is refused rather than quietly rewritten.
//
// It is the same desk read either way. What changed is that the thing policy cares about is now
// in the request, which is the only place policy can look.
@id("auditor-may-fetch-export-rows")
permit (
  principal in Role::"auditor",
  action == Action::"desk.fetch_rows",
  resource == Tool::"exports"
);
