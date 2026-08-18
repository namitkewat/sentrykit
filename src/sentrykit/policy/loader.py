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

So adopting a pattern is a matter of putting an attribute on an entity, which is data — which
is the whole of ADR-005 restated for the pack.

## The schema is opt-in, and the reason matters

``pack.cedarschema`` ships with the pack, but :meth:`PackPolicySource.load` does **not** put
it on the bundle unless asked (``pack://?schema=true``). A composite concatenates its members'
schemas, and a Cedar engine built *with* a schema validates every request against it — so a
pack that contributed a schema by default would make every request naming an action the pack
never heard of fail to parse, in an application that was working a moment earlier. Phase 5
research measured the pack's decisions to be identical with and without the schema, so the
default costs nothing and the opt-in is a real choice rather than a workaround.

When you do opt in, your own schema must declare only what the pack does not: redeclaring
``User``, ``Role``, ``Group`` or ``Resource`` is a Cedar schema parse error
(``` `User` is declared twice ```). Adding actions is safe, and an action whose context is
``{}`` still type-checks against the pack's ``context has now`` conditions.

## Templates are linked here, not by Cedar

``cedarpy`` 4.8.7 exposes no template-linking API at all (phase 5 research §5), and an
unlinked template in a policy set is inert. :func:`link_template` therefore performs the
link on our side — textual substitution of ``?principal`` and ``?resource`` — and returns the
concrete policy *and* the matching :class:`~sentrykit.stores.base.GrantSpec` together, since
a time-boxed grant is a rule and a piece of data at the same time.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

from sentrykit.cedar import EntityRef
from sentrykit.registry import register_policy_source
from sentrykit.stores.base import GrantSpec, PolicyBundle

if TYPE_CHECKING:  # pragma: no cover - imported for annotations only
    from collections.abc import Mapping, Sequence

    from sentrykit.registry import DSN

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
        obligations: The obligations the pattern's permits carry, if any (ADR-012).
    """

    name: str
    file: str
    summary: str
    policy_ids: tuple[str, ...]
    requires: tuple[str, ...] = ()
    obligations: tuple[str, ...] = ()


PATTERNS: Final[Mapping[str, PackPattern]] = {}
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
    raise NotImplementedError


def pack_template(name: str) -> str:
    """Return one shipped Cedar template's text.

    Args:
        name: The template's name, with or without the :data:`TEMPLATE_SUFFIX` suffix.

    Returns:
        The template text, with its ``?principal`` / ``?resource`` slots unfilled.

    Raises:
        ConfigurationError: If no such template ships with the pack.
    """
    raise NotImplementedError


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
        raise NotImplementedError

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
        raise NotImplementedError

    @property
    def name(self) -> str:
        """Short name for this source, used to namespace policy ids and tag provenance."""
        raise NotImplementedError

    @property
    def patterns(self) -> tuple[PackPattern, ...]:
        """The patterns this source contributes, in concatenation order."""
        raise NotImplementedError

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
        raise NotImplementedError

    def current_hash(self) -> str:
        """Return the digest of the artifact :meth:`load` would return right now."""
        raise NotImplementedError


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
    raise NotImplementedError


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

    ``cedarpy`` has no linking API (phase 5 research §5), so the link is textual: every
    ``?principal`` becomes the principal's uid and every ``?resource`` becomes the resource's,
    an ``@id(link_id)`` annotation is prepended, and — when ``expires_at`` is given — a
    ``when { context.now <= <epoch> }`` condition is appended so the policy stops permitting
    on its own. Epoch seconds, because
    :func:`~sentrykit.cedar.coerce_value` renders every ``datetime`` that way and Cedar has no
    ordering on strings.

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
    raise NotImplementedError


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
        raise NotImplementedError

    @property
    def name(self) -> str:
        """Short name for this source."""
        raise NotImplementedError

    @property
    def links(self) -> tuple[TemplateLink, ...]:
        """The links this source contributes, in order."""
        raise NotImplementedError

    def load(self) -> PolicyBundle:
        """Build a bundle from the linked policies.

        Returns:
            The bundle, with each link's :attr:`~TemplateLink.link_id` as its policy id.

        Raises:
            ConfigurationError: If the concatenated links do not parse.
        """
        raise NotImplementedError

    def current_hash(self) -> str:
        """Return the digest of the artifact :meth:`load` would return right now."""
        raise NotImplementedError
