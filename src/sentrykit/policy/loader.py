"""The shipped Cedar policy pack, loaded as an ordinary policy source.

The pack is **data, not a second policy mechanism**. It reaches a governor through exactly
the machinery a user's own directory does — a :class:`~sentrykit.stores.base.PolicySource`
registered under the ``sentrykit.policy_sources`` entry-point group, addressed by DSN,
unioned by :class:`~sentrykit.stores.composite.CompositePolicySource`:

```python
install(policy_source=["pack://", "file://./policies"])
```

That union namespaces the pack's declared ids as ``pack/<id>``, so an audit record for a
decision the pack made names the pack, and a decision one of your own policies made names
your directory. Nothing about the pack is privileged: drop the DSN and it is not there.

## Every pattern is attribute-driven

A shipped pack cannot know your role names, your resource types or your actions, so none of
its policies name any. Each pattern reads the *shape* of the request instead:

* the **resource** declares what it requires (``required_role``, ``group``, ``owner``,
  ``emergency_only``, ``emergency_role``, ``conflicting_role``, ``prepared_by``);
* the **grant store** supplies the principal's edges and attributes;
* the **context** supplies ``now``, ``break_glass``, ``on_behalf_of`` and ``justification``.

So adopting a pattern is a matter of putting an attribute on an entity, which is data. The
policy logic itself stays reviewed in version control and is never rewritten at runtime.

## The schema is opt-in, and the reason matters

``pack.cedarschema`` ships with the pack, but :meth:`PackPolicySource.load` does **not** put
it on the bundle unless asked (``pack://?schema=true``). A composite concatenates its members'
schemas, and a Cedar engine built *with* a schema validates every request against it — so a
pack that contributed a schema by default would make every request naming an action the pack
never heard of fail to parse, in an application that was working a moment earlier. The pack's
decisions are identical with and without the schema, so the default costs nothing and the
opt-in is a real choice rather than a workaround.

When you do opt in, your own schema must declare only what the pack does not: redeclaring
``User``, ``Role``, ``Group`` or ``Resource`` is a Cedar schema parse error
(``` `User` is declared twice ```). Adding actions is safe, and an action whose context is
``{}`` still type-checks against the pack's ``context has now`` conditions.

## Templates are linked here, not by Cedar

``cedarpy`` 4.8.7 exposes no template-linking API at all, and an unlinked template in a
policy set is inert. :func:`link_template` therefore performs the
link on our side — textual substitution of ``?principal`` and ``?resource`` — and returns the
concrete policy *and* the matching :class:`~sentrykit.stores.base.GrantSpec` together, since
a time-boxed grant is a rule and a piece of data at the same time.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

from sentrykit.cedar import EntityRef, coerce_value, policy_annotations, validate_policies
from sentrykit.errors import ConfigurationError
from sentrykit.registry import register_policy_source
from sentrykit.stores.base import GrantSpec, PolicyBundle, PolicyProvenance
from sentrykit.stores.filesystem import FilesystemPolicySource

if TYPE_CHECKING:  # pragma: no cover - imported for annotations only
    from collections.abc import Mapping, Sequence

    from sentrykit.registry import DSN

_LOGGER: Final = logging.getLogger("sentrykit.policy.loader")

__all__ = [
    "PACK_NAME",
    "PATTERNS",
    "SCHEMA_FILE",
    "TEMPLATE_SUFFIX",
    "LinkedPolicySource",
    "PackPattern",
    "PackPolicySource",
    "TemplateLink",
    "link_template",
    "load_pack",
    "pack_root",
    "pack_schema",
    "pack_template",
]

PACK_NAME: Final = "pack"
"""Default source name, and therefore the namespace declared ids appear under in a union."""

SCHEMA_FILE: Final = "pack.cedarschema"
"""The pack's Cedar schema, shipped alongside the policies and loaded only on request."""

TEMPLATE_SUFFIX: Final = ".cedartemplate"
"""Templates live under ``pack/templates/`` with this suffix, deliberately outside the
``*.cedar`` glob: an unlinked template can never permit anything, so loading one as if it
were a policy would put something inert into a reviewed policy set."""

_TEMPLATE_DIR: Final = "templates"
"""Subdirectory of the pack holding :data:`TEMPLATE_SUFFIX` files."""

_ENTITIES_FILE: Final = "entities.json"
"""The pack's stable entity graph. One node — the ``Action::"approve"`` group the
separation-of-duties forbid names — because a shipped pack has no principals and no
resources of its own to declare."""

_SLOT_RE: Final = re.compile(r"\?([A-Za-z_][A-Za-z0-9_]*)")
"""A Cedar template slot. Only ``?principal`` and ``?resource`` exist, but the pattern is
written generally so an unfillable slot is *reported* rather than silently left in the text —
a policy still carrying ``?action`` parses as a template and is inert."""


@dataclass(frozen=True, slots=True)
class PackPattern:
    """One shipped pattern: what it is, which file holds it, and what it declares.

    Attributes:
        name: The pattern's short name, as it is spelled in a ``pack://<names>`` DSN.
        file: The policy file, relative to the pack root.
        summary: One sentence, in authorization vocabulary, on what the pattern decides.
        policy_ids: The ``@id`` annotations the file declares, in file order. These are the
            names a decision reports as determining, and ``<pack-name>/<id>`` once unioned.
        requires: The entity attributes and context keys the pattern reads, so a host can
            tell what data adopting it needs. Spelled ``resource.owner``, ``context.now``,
            ``principal.elevation_until``.
        obligations: The obligations the pattern's permits carry, if any.
    """

    name: str
    file: str
    summary: str
    policy_ids: tuple[str, ...]
    requires: tuple[str, ...] = ()
    obligations: tuple[str, ...] = ()


PATTERNS: Final[Mapping[str, PackPattern]] = {
    "rbac": PackPattern(
        name="rbac",
        file="10-rbac.cedar",
        summary="A principal holding the role the resource requires may act on it.",
        policy_ids=("rbac-required-role",),
        requires=("resource.required_role",),
    ),
    "groups": PackPattern(
        name="groups",
        file="20-groups.cedar",
        summary="A member of the group the resource belongs to may act on it, at any depth.",
        policy_ids=("group-membership",),
        requires=("resource.group",),
    ),
    "ownership": PackPattern(
        name="ownership",
        file="30-ownership.cedar",
        summary="The owner of a resource may act on it; ownership is not inherited.",
        policy_ids=("resource-owner",),
        requires=("resource.owner",),
    ),
    "delegation": PackPattern(
        name="delegation",
        file="40-delegation.cedar",
        summary=(
            "A principal may act on behalf of its delegator, but only within the delegated "
            "scope and only until the delegation lapses."
        ),
        policy_ids=(
            "delegation-on-behalf-of",
            "delegation-outside-scope-forbidden",
            "delegation-expired-forbidden",
        ),
        requires=(
            "principal.delegated_by",
            "principal.delegated_actions",
            "principal.delegation_expires",
            "resource.required_role",
            "context.on_behalf_of",
            "context.now",
        ),
        obligations=("record:on_behalf_of",),
    ),
    "expiry": PackPattern(
        name="expiry",
        file="50-expiry.cedar",
        summary="An entitlement window that refuses the call outside its bounds.",
        policy_ids=(
            "entitlement-expired-forbidden",
            "entitlement-not-yet-valid-forbidden",
        ),
        requires=(
            "principal.entitlement_starts",
            "principal.entitlement_expires",
            "context.now",
        ),
    ),
    "break-glass": PackPattern(
        name="break-glass",
        file="60-break-glass.cedar",
        summary=(
            "An emergency-only resource is refused outright unless the caller raises the "
            "flag, and is then reachable only by a principal entitled to the emergency, "
            "carrying a justification."
        ),
        policy_ids=(
            "emergency-resource-forbidden-without-flag",
            "break-the-glass",
        ),
        requires=(
            "resource.emergency_only",
            "resource.emergency_role",
            "context.break_glass",
            "context.justification",
        ),
        obligations=("notify:secops", "record:justification"),
    ),
    "separation-of-duties": PackPattern(
        name="separation-of-duties",
        file="70-separation-of-duties.cedar",
        summary=(
            "A conflicting role is refused the resource outright, and nobody approves what "
            "they prepared themselves."
        ),
        policy_ids=("sod-conflicting-role", "sod-same-actor-approval"),
        requires=("resource.conflicting_role", "resource.prepared_by"),
    ),
    "jit-elevation": PackPattern(
        name="jit-elevation",
        file="80-jit-elevation.cedar",
        summary=(
            "A principal holds an elevated role for a window, and is refused once the "
            "window closes."
        ),
        policy_ids=("jit-elevation", "jit-elevation-expired-forbidden"),
        requires=(
            "principal.elevation_role",
            "principal.elevation_until",
            "resource.required_role",
            "context.now",
        ),
        obligations=("notify:secops",),
    ),
}
"""Every shipped pattern, keyed by name, in the order the files are concatenated.

Declared in Python rather than in a manifest file beside the policies because it is *typed*,
and because a second file listing the first is a second thing to keep in step. The tests
assert the table and the directory agree.
"""


def pack_root() -> Path:
    """Return the directory the shipped pack lives in.

    Resolved from ``__file__`` rather than through :mod:`importlib.resources`, because the
    pack is read as a *directory* by :class:`~sentrykit.stores.filesystem.FilesystemPolicySource`
    and ``files()`` yields a ``Traversable`` that is only a real path for the ordinary
    (non-zipped) install. sentrykit does not support running from a zipimport, and saying so
    here is better than a context manager that pretends otherwise.

    Returns:
        The absolute path of ``sentrykit/policy/pack``.
    """
    return Path(__file__).parent / "pack"


def pack_schema() -> str:
    """Return the pack's Cedar schema text.

    Returns:
        The contents of ``pack.cedarschema``.

    Raises:
        ConfigurationError: If the shipped schema is missing, which means a broken install.
    """
    return _read(pack_root() / SCHEMA_FILE, "the shipped policy pack's cedar schema")


def pack_template(name: str) -> str:
    """Return one shipped Cedar template's text.

    Args:
        name: The template's name, with or without the :data:`TEMPLATE_SUFFIX` suffix.

    Returns:
        The template text, with its ``?principal`` / ``?resource`` slots unfilled.

    Raises:
        ConfigurationError: If no such template ships with the pack.
    """
    stem = name[: -len(TEMPLATE_SUFFIX)] if name.endswith(TEMPLATE_SUFFIX) else name
    directory = pack_root() / _TEMPLATE_DIR
    path = directory / f"{stem}{TEMPLATE_SUFFIX}"
    if not path.is_file():
        known = ", ".join(sorted(found.stem for found in directory.glob(f"*{TEMPLATE_SUFFIX}")))
        raise ConfigurationError(
            f"no template named {name!r} ships with the policy pack; available: {known or 'none'}"
        )
    return _read(path, f"the shipped template {stem!r}")


@register_policy_source(PACK_NAME)
class PackPolicySource:
    """The shipped policy pack, as a :class:`~sentrykit.stores.base.PolicySource`.

    Args:
        patterns: Which patterns to include. Empty — the default — means every one of them.
            An unknown name is a configuration error rather than a silent omission, because
            a pattern that is quietly absent is a permit that quietly never fires.
        name: The source name, which becomes the namespace for its policy ids in a union.
            Change it when you ship a second, differently-configured pack alongside.
        schema: Whether to put :data:`SCHEMA_FILE` on the loaded bundle. Off by default; see
            the module docstring for why that default is the safe one.
        validate: Whether to type-check the pack against its own schema at load. Independent
            of ``schema``: validation happens against the shipped schema either way, and only
            the *bundle's* schema is affected by ``schema``.

    Example:
        ```python
        install(policy_source=["pack://ownership,rbac", "file://./policies"])
        ```
    """

    __slots__ = ("_name", "_patterns", "_schema", "_validate")

    def __init__(
        self,
        *,
        patterns: Sequence[str] = (),
        name: str = PACK_NAME,
        schema: bool = False,
        validate: bool = True,
    ) -> None:
        self._patterns = _selected(patterns)
        self._name = name
        self._schema = schema
        self._validate = validate

    @classmethod
    def from_dsn(cls, dsn: DSN) -> PackPolicySource:
        """Build from ``pack://[pattern,pattern]?name=...&schema=...&validate=...``.

        The DSN target is a comma-separated list of pattern names; an empty target means the
        whole pack. ``pack`` on its own parses as ``pack://`` and means the same thing.

        Args:
            dsn: The parsed address.

        Returns:
            The source.

        Raises:
            ConfigurationError: If a named pattern does not ship, or an option is malformed.
        """
        return cls(
            patterns=tuple(part.strip() for part in dsn.target.split(",") if part.strip()),
            name=dsn.option("name") or PACK_NAME,
            schema=dsn.flag("schema", False),
            validate=dsn.flag("validate", True),
        )

    @property
    def name(self) -> str:
        """Short name for this source, used to namespace policy ids and tag provenance."""
        return self._name

    @property
    def patterns(self) -> tuple[PackPattern, ...]:
        """The patterns this source contributes, in concatenation order."""
        return self._patterns

    def load(self) -> PolicyBundle:
        """Read the shipped pack and build the bundle.

        Returns:
            The bundle, with one provenance entry per policy naming the pattern file it came
            from as its ``origin``, and :attr:`~sentrykit.stores.base.PolicyBundle.schema`
            set only when the source was built with ``schema=True``.

        Raises:
            ConfigurationError: If the shipped pack is missing, unparseable, or fails
                validation against its own schema — all of which mean a broken install.
        """
        bundles = [reader.load() for reader in self._readers()]
        # Each member read exactly one file, so joining their texts with a newline reproduces
        # what a single ``FilesystemPolicySource`` over the whole directory would have built —
        # and doing it here is what lets a subset skip files a glob cannot express.
        combined = "\n".join(bundle.policies for bundle in bundles)
        schema = pack_schema()
        if self._validate:
            self._validate_against(combined, schema)

        bundle = PolicyBundle.from_text(
            combined,
            # Opt-in, because a composite concatenates its members' schemas and an engine
            # built with one validates every request against it: a pack that contributed a
            # schema by default would refuse every action it had never heard of.
            schema=schema if self._schema else None,
            # Every member read the same directory, so they all picked up the same entity
            # graph; the first one's is that graph.
            entities=bundles[0].entities,
            source=self._name,
            origin=str(pack_root()),
        )
        origins = tuple(entry.origin for member in bundles for entry in member.provenance)
        _LOGGER.debug(
            "Loaded the shipped cedar policy pack",
            extra={
                "source": self._name,
                "patterns": [pattern.name for pattern in self._patterns],
                "policies": len(bundle.provenance),
                "bundle_hash": bundle.bundle_hash,
                "schema": self._schema,
            },
        )
        return replace(bundle, provenance=_with_origins(bundle, origins))

    def current_hash(self) -> str:
        """Return the digest of the artifact :meth:`load` would return right now.

        Loads to compute it. The pack ships inside the distribution and cannot change under a
        running process, so a cheaper stat-based shortcut would be optimizing a poll nobody
        needs to make — and it would have to reproduce the schema opt-in, which is the one
        thing about this source's digest that is not simply "what is on disk".
        """
        return self.load().bundle_hash

    def _readers(self) -> tuple[FilesystemPolicySource, ...]:
        """One filesystem source per selected pattern file, in table order.

        Delegated rather than reimplemented: the directory shape is exactly the one
        :class:`~sentrykit.stores.filesystem.FilesystemPolicySource` was written for, and it
        already owns per-file ``origin``, entity-JSON parsing and the "this file is not valid
        cedar" error. One reader per file is what makes a *subset* expressible, since a single
        glob cannot say "these three of the eight".

        Raises:
            ConfigurationError: If a pattern's file is missing, which means a broken install.
        """
        root = pack_root()
        missing = [
            pattern.file for pattern in self._patterns if not (root / pattern.file).is_file()
        ]
        if missing:
            raise ConfigurationError(
                f"the shipped policy pack at {str(root)!r} is missing {', '.join(missing)}; "
                "the sentrykit install is incomplete"
            )
        return tuple(
            FilesystemPolicySource(
                root,
                name=self._name,
                pattern=pattern.file,
                # Validation happens once, against the combined text: a policy set is
                # type-checked as a whole, and eight per-file runs would report the same
                # schema fault eight times.
                validate=False,
                entities_name=_ENTITIES_FILE,
            )
            for pattern in self._patterns
        )

    def _validate_against(self, policies: str, schema: str) -> None:
        """Type-check the pack against its own shipped schema.

        A failure here is not a user's misconfiguration — the pack and the schema ship in the
        same distribution — so the message says so rather than inviting someone to go and fix
        their policies.

        Raises:
            ConfigurationError: If validation did not pass.
        """
        outcome = validate_policies(policies, schema)
        if outcome.passed:
            return
        raise ConfigurationError(
            f"the shipped policy pack failed cedar validation against {SCHEMA_FILE}: "
            f"{outcome.describe()}; the sentrykit install is broken"
        )


def load_pack(
    *,
    patterns: Sequence[str] = (),
    schema: bool = False,
    name: str = PACK_NAME,
) -> PolicyBundle:
    """Load the shipped pack directly, without going through a DSN.

    Args:
        patterns: Which patterns to include; empty means all of them.
        schema: Whether the bundle carries the pack's schema.
        name: The source name recorded on every provenance entry.

    Returns:
        The bundle.

    Raises:
        ConfigurationError: If a named pattern does not ship, or the install is broken.
    """
    return PackPolicySource(patterns=patterns, name=name, schema=schema).load()


@dataclass(frozen=True, slots=True)
class TemplateLink:
    """A linked template: one concrete policy, and the grant that records it as data.

    Both halves describe the same authorization fact, for two different audiences. The
    :attr:`policy` is reviewed logic a Cedar engine can decide against; the :attr:`grant` is
    the store record an admin surface lists, an auditor queries, and a revocation targets.

    Attributes:
        link_id: The ``@id`` written onto the generated policy, and the id the grant carries.
        policy: Concrete Cedar policy text, with the template's slots filled and an expiry
            condition appended when one was asked for.
        grant: The matching grant, carrying the same principal, subject and expiry.
        template: The template text the link was made from, kept for provenance.
    """

    link_id: str
    policy: str
    grant: GrantSpec
    template: str = ""


def link_template(
    template: str,
    *,
    link_id: str,
    principal: str | EntityRef,
    resource: str | EntityRef,
    expires_at: datetime | None = None,
    granted_by: str | None = None,
    reason: str | None = None,
) -> TemplateLink:
    """Link a Cedar template into a concrete policy, and the grant that records it.

    ``cedarpy`` has no linking API, so the link is textual: every
    ``?principal`` becomes the principal's uid and every ``?resource`` becomes the resource's,
    an ``@id(link_id)`` annotation is prepended, and — when ``expires_at`` is given — a
    ``when { context has now && context.now <= <epoch> }`` condition is appended so the policy
    stops permitting on its own. Epoch seconds, because
    :func:`~sentrykit.cedar.coerce_value` renders every ``datetime`` that way and Cedar has no
    ordering on strings; guarded by ``has``, because Cedar's validator refuses an
    unconditional read of an optional context attribute and a link that evaluated correctly
    but failed ``sentrykit policy validate`` would be a trap.

    Args:
        template: The template text, from :func:`pack_template` or your own file.
        link_id: The id for this link. Must be unique across the policy set; it is what a
            decision reports and what an auditor joins on.
        principal: Who the link is for.
        resource: What it is over.
        expires_at: When it stops applying. ``None`` means it does not expire — which is a
            standing grant, not a time-boxed one, and is worth being deliberate about.
        granted_by: The actor making the grant, recorded on the grant.
        reason: The justification, recorded on the grant.

    Returns:
        The link.

    Raises:
        ConfigurationError: If the template declares no slots, if a slot is left unfilled, or
            if ``link_id`` is empty.
    """
    identifier = link_id.strip()
    if not identifier:
        raise ConfigurationError(
            "a template link needs a non-empty link_id; it is the name a decision reports "
            "and the subject an auditor joins the grant on"
        )
    if not _SLOT_RE.search(template):
        raise ConfigurationError(
            f"the template linked as {identifier!r} declares no ?principal or ?resource slot; "
            "it is already a concrete policy, and linking it would only copy it"
        )

    principal_ref = EntityRef.parse(principal, default_type="User")
    resource_ref = EntityRef.parse(resource, default_type="Resource")
    body = template.replace("?principal", str(principal_ref)).replace(
        "?resource", str(resource_ref)
    )
    unfilled = sorted({f"?{slot}" for slot in _SLOT_RE.findall(body)})
    if unfilled:
        raise ConfigurationError(
            f"the template linked as {identifier!r} still declares {', '.join(unfilled)} after "
            "linking; only ?principal and ?resource can be filled"
        )

    policy = f'@id("{identifier}")\n{body.strip()}'
    if expires_at is not None:
        # Appended rather than woven in: Cedar accepts chained ``when`` clauses, so this is
        # safe even for a template that already carries one, and the expiry stays visibly the
        # thing sentrykit added rather than something the reviewed template said.
        #
        # Guarded with ``context has now`` even though the engine always injects it. Without
        # the guard the clause reads an optional attribute unconditionally, which Cedar's
        # validator refuses ("unable to guarantee safety of access to optional attribute
        # 'now'") -- so an unguarded link would evaluate fine and fail `sentrykit policy
        # validate` the day anyone wrote one out to a directory. The two spellings agree at
        # runtime, and the guarded one fails closed if `now` is ever absent.
        condition = f"when {{ context has now && context.now <= {_epoch(expires_at)} }};"
        policy = f"{policy.rstrip().rstrip(';').rstrip()}\n{condition}"

    return TemplateLink(
        link_id=identifier,
        policy=f"{policy}\n",
        grant=GrantSpec(
            principal=principal_ref,
            kind="attribute",
            subject=identifier,
            value=str(resource_ref),
            granted_by=granted_by,
            expires_at=expires_at,
            reason=reason,
        ),
        template=template,
    )


class LinkedPolicySource:
    """Linked templates, as a policy source that composes like any other.

    Held in memory rather than written to a directory, because a link is generated logic: it
    is derived from a reviewed template plus a piece of grant data, and round-tripping it
    through a file would invite someone to edit the derived half.

    Args:
        links: The links to contribute, in order.
        name: The source name, and therefore the namespace for the links' ids in a union.

    Example:
        ```python
        link = link_template(pack_template("time-boxed-grant"), link_id="oncall-ana",
                             principal='User::"ana"', resource='Resource::"paging"',
                             expires_at=end_of_shift)
        install(policy_source=["pack://", LinkedPolicySource([link])])
        ```
    """

    __slots__ = ("_links", "_name")

    def __init__(self, links: Sequence[TemplateLink], *, name: str = "linked") -> None:
        self._links = tuple(links)
        self._name = name

    @property
    def name(self) -> str:
        """Short name for this source."""
        return self._name

    @property
    def links(self) -> tuple[TemplateLink, ...]:
        """The links this source contributes, in order."""
        return self._links

    def load(self) -> PolicyBundle:
        """Build a bundle from the linked policies.

        No links is not an error: "nobody currently holds a time-boxed grant" is the ordinary
        resting state of this source, and a union that refused to build in that state would
        take the whole policy set down every time the last link expired.

        Returns:
            The bundle, with each link's :attr:`~TemplateLink.link_id` as its policy id.

        Raises:
            ConfigurationError: If the concatenated links do not parse.
        """
        combined = "\n\n".join(link.policy.strip() for link in self._links)
        bundle = PolicyBundle.from_text(combined, source=self._name)
        origins = tuple(
            f"link:{link.link_id}"
            for link in self._links
            for _ in range(len(policy_annotations(link.policy)))
        )
        return replace(bundle, provenance=_with_origins(bundle, origins))

    def current_hash(self) -> str:
        """Return the digest of the artifact :meth:`load` would return right now.

        The links are held in memory, so this is the digest of what the process currently
        holds — it changes as links are added or dropped, which is exactly the signal a caller
        polling for a reload is after.
        """
        return self.load().bundle_hash


# --- helpers -----------------------------------------------------------------------------


def _selected(names: Sequence[str]) -> tuple[PackPattern, ...]:
    """Resolve pattern names to patterns, in :data:`PATTERNS` order.

    The table's order wins over the caller's, because it is the order the files concatenate
    in and Cedar numbers policies positionally: letting ``pack://ownership,rbac`` and
    ``pack://rbac,ownership`` produce two different bundles would make the provenance index
    depend on how somebody typed a DSN.

    Args:
        names: The requested pattern names. Empty means every pattern.

    Returns:
        The selected patterns.

    Raises:
        ConfigurationError: If a name does not ship. A pattern that was quietly dropped is a
            permit that quietly never fires, so this is never a silent omission.
    """
    wanted = [name.strip() for name in names if name.strip()]
    if not wanted:
        return tuple(PATTERNS.values())
    unknown = sorted({name for name in wanted if name not in PATTERNS})
    if unknown:
        raise ConfigurationError(
            f"the shipped policy pack has no pattern named {', '.join(repr(n) for n in unknown)}; "
            f"available: {', '.join(PATTERNS)}"
        )
    chosen = set(wanted)
    return tuple(pattern for name, pattern in PATTERNS.items() if name in chosen)


def _with_origins(bundle: PolicyBundle, origins: Sequence[str]) -> tuple[PolicyProvenance, ...]:
    """Stitch a per-policy ``origin`` onto a bundle built from concatenated text.

    The combined parse knows the policies but not which artifact each came from, so the
    origins are aligned positionally — the same reconciliation
    :class:`~sentrykit.stores.filesystem.FilesystemPolicySource` performs, for the same
    reason: the index must come from one parse of one string.
    """
    return tuple(
        replace(entry, origin=origins[position]) if position < len(origins) else entry
        for position, entry in enumerate(bundle.provenance)
    )


def _epoch(moment: datetime) -> int:
    """Render a moment as the epoch seconds a Cedar ``Long`` comparison needs.

    Delegated to :func:`~sentrykit.cedar.coerce_value` rather than computed here, so a linked
    template's expiry and a ``context.now`` established by the engine are produced by exactly
    one piece of code — including its rule that a naive timestamp is read as UTC.

    Raises:
        ConfigurationError: If the value has no Cedar representation, which would leave the
            expiry condition unwritable.
    """
    seconds = coerce_value(moment)
    if not isinstance(seconds, int):  # pragma: no cover - datetimes always coerce to Long
        raise ConfigurationError(f"cannot express {moment!r} as an epoch-second expiry")
    return seconds


def _read(path: Path, what: str) -> str:
    """Read one shipped UTF-8 file, reporting a missing one as the broken install it is.

    Raises:
        ConfigurationError: If the file is absent or cannot be decoded.
    """
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigurationError(f"cannot read {what} at {str(path)!r}: {exc}") from exc
