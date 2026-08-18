"""The zero-config policy source: Cedar policy logic read from a directory on disk.

ADR-005 makes policy *logic* an artifact that is authored in git and reviewed before it
ships. This is the local end of that pipeline — the same directory a developer edits, and the
same one a build step syncs out of a versioned S3 prefix — so what runs in a test is loaded
by the identical code path that will later load the deployed bundle.

Three details are load-bearing rather than incidental:

* **Files are read in sorted order.** Cedar numbers policies positionally in the text it
  parsed, so the concatenation order decides the generated ``policyN`` ids. A load in
  directory order would produce a different provenance index per machine.
* **The bundle is built from one string.** The combined text is assembled first, and both the
  :class:`~sentrykit.cedar.PolicyEngine` and the annotation index come out of it — per phase
  2 research §3, deriving the index from anything else silently mis-joins every decision.
  Per-file ``origin`` is then stitched back on by counting how many policies each file
  contributed, which is the one thing the combined parse cannot tell us.
* **Validation is reported, not raised.** Cedar reports a policy parse error, a schema
  parse error and a type error identically — as entries in ``errors`` with
  ``validation_passed`` false — so branching on the flag is the only way to notice.
  :func:`~sentrykit.cedar.validate_policies` normalizes that, which also keeps ``cedarpy``
  confined to one module.
"""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from pathlib import Path
from typing import Final

from sentrykit.cedar import Entity, EntityRef, policy_annotations, validate_policies
from sentrykit.errors import ConfigurationError
from sentrykit.registry import DSN, register_policy_source
from sentrykit.stores.base import PolicyBundle, _bundle_hash

__all__ = ["SCHEMA_PATTERN", "FilesystemPolicySource"]

_LOGGER: Final = logging.getLogger("sentrykit.stores.filesystem")

SCHEMA_PATTERN: Final = "*.cedarschema"
"""What a schema file is called when the source is left to find one itself.

Cedar *schema syntax*, not the JSON form: phase 2 research established that
``cedarpy.Schema.from_str`` rejects the JSON schema with ``unexpected token '{'``.
"""


@register_policy_source("file")
class FilesystemPolicySource:
    """Cedar policies, a schema and a stable entity graph, loaded from one directory.

    Args:
        path: The directory to read. Every file matching ``pattern`` in it is a policy file.
        name: Short name for this source, recorded on every provenance entry.
        schema_path: An explicit schema file. When omitted, a single ``*.cedarschema`` in the
            directory is used, and having none is not an error — it only turns validation off.
        validate: Whether to type-check the policies against the schema at load.
            Catching an unsatisfiable policy at wiring time is much better than watching it
            deny every request at runtime, so this defaults on.
        pattern: Glob for policy files, relative to ``path``. ``**/*.cedar`` works when a
            deployment wants nested directories.
        entities_name: Cedar entity JSON in the directory, holding the stable graph — roles,
            teams, tools. Absent is fine. Principals never belong here: they come from a
            :class:`~sentrykit.stores.base.GrantStore`, per request.

    Example:
        ```python
        source = FilesystemPolicySource("./policies")
        bundle = source.load()
        governor = Governor(bundle.engine())
        ```
    """

    __slots__ = ("_entities_name", "_name", "_path", "_pattern", "_schema_path", "_validate")

    def __init__(
        self,
        path: str | Path,
        *,
        name: str = "file",
        schema_path: str | Path | None = None,
        validate: bool = True,
        pattern: str = "*.cedar",
        entities_name: str = "entities.json",
    ) -> None:
        self._path = Path(path)
        self._name = name
        self._schema_path = Path(schema_path) if schema_path is not None else None
        self._validate = validate
        self._pattern = pattern
        self._entities_name = entities_name

    @classmethod
    def from_dsn(cls, dsn: DSN) -> FilesystemPolicySource:
        """Build from ``file://<directory>?name=...&schema=...&validate=...&pattern=...``.

        The source's name defaults to the **directory's own name**, not to the scheme. That
        matters as soon as two directories are unioned: a composite namespaces policy ids by
        source name and refuses two members that share one, so a pair of sources both called
        ``file`` would make the ordinary
        ``["file://./policies/base", "file://./policies/tenant-a"]`` wiring unusable. Set
        ``?name=`` when the directory names collide or read badly in an audit record.

        Args:
            dsn: The parsed address. ``name`` overrides the derived source name, ``schema``
                names a schema file, ``validate`` is a boolean, ``pattern`` overrides the
                policy-file glob.

        Returns:
            The source.

        Raises:
            ConfigurationError: If the DSN names no directory, or an option is malformed.
        """
        if not dsn.target.strip():
            raise ConfigurationError(f"{dsn.raw!r} names no policy directory")
        return cls(
            dsn.target,
            name=dsn.option("name") or _derived_name(dsn.target) or dsn.scheme,
            schema_path=dsn.option("schema"),
            validate=dsn.flag("validate", True),
            pattern=dsn.option("pattern") or "*.cedar",
        )

    @property
    def name(self) -> str:
        """Short name for this source, used to namespace policy ids and tag provenance."""
        return self._name

    @property
    def path(self) -> Path:
        """The directory this source reads."""
        return self._path

    def load(self) -> PolicyBundle:
        """Read the directory and build the bundle.

        Returns:
            The bundle, with one provenance entry per policy naming the file it came from.

        Raises:
            ConfigurationError: If the directory is missing, holds no matching files, fails
                to parse, or fails schema validation.
        """
        sources = self._read()
        schema = self._read_schema()
        combined = _combine(sources)

        origins = self._origins(sources)
        if self._validate and schema is not None:
            self._validate_against(combined, schema)

        bundle = PolicyBundle.from_text(
            combined,
            schema=schema,
            entities=self._read_entities(),
            source=self._name,
            origin=str(self._path),
        )
        provenance = tuple(
            replace(entry, origin=origins[position]) if position < len(origins) else entry
            for position, entry in enumerate(bundle.provenance)
        )
        _LOGGER.debug(
            "Loaded cedar policies from disk",
            extra={
                "source": self._name,
                "path": str(self._path),
                "files": len(sources),
                "policies": len(provenance),
                "bundle_hash": bundle.bundle_hash,
                "schema": schema is not None,
            },
        )
        return replace(bundle, provenance=provenance)

    def current_hash(self) -> str:
        """Digest the policy text and schema **as they are on disk right now**.

        Deliberately re-reads rather than caching: the point of a pollable hash is to notice
        that somebody edited a file, and a cached value would never notice anything.

        Returns:
            The same digest :meth:`load` puts on the bundle.

        Raises:
            ConfigurationError: If the directory is missing or holds no matching files.
        """
        return _bundle_hash(_combine(self._read()), self._read_schema())

    def _read(self) -> tuple[tuple[Path, str], ...]:
        """Read every policy file the pattern matches.

        Returns:
            ``(path, text)`` pairs, sorted by path so the concatenation — and therefore
            Cedar's positional policy numbering — is identical on every machine.

        Raises:
            ConfigurationError: If the directory is missing or matches nothing.
        """
        if not self._path.is_dir():
            raise ConfigurationError(
                f"policy source {self._name!r} cannot read {str(self._path)!r}: "
                "it is not a directory"
            )
        paths = sorted(path for path in self._path.glob(self._pattern) if path.is_file())
        if not paths:
            # An empty policy set denies everything, which is safe but silent. A source
            # pointed at the wrong directory should say so at wiring time instead.
            raise ConfigurationError(
                f"policy source {self._name!r} found no files matching {self._pattern!r} "
                f"in {str(self._path)!r}"
            )
        return tuple((path, _read_text(path)) for path in paths)

    def _read_schema(self) -> str | None:
        """Read the Cedar schema, if there is one.

        Raises:
            ConfigurationError: If an explicit ``schema_path`` is missing, or if the
                directory holds more than one schema file and so cannot be guessed at.
        """
        if self._schema_path is not None:
            if not self._schema_path.is_file():
                raise ConfigurationError(
                    f"policy source {self._name!r} cannot read schema "
                    f"{str(self._schema_path)!r}: no such file"
                )
            return _read_text(self._schema_path)
        if not self._path.is_dir():
            return None
        found = sorted(path for path in self._path.glob(SCHEMA_PATTERN) if path.is_file())
        if not found:
            return None
        if len(found) > 1:
            raise ConfigurationError(
                f"policy source {self._name!r} found {len(found)} schema files in "
                f"{str(self._path)!r} ({', '.join(path.name for path in found)}); "
                "name one explicitly with schema_path"
            )
        return _read_text(found[0])

    def _read_entities(self) -> tuple[Entity, ...]:
        """Read the stable entity graph, if the directory ships one.

        Raises:
            ConfigurationError: If the file is present but is not Cedar entity JSON.
        """
        path = self._path / self._entities_name
        if not path.is_file():
            return ()
        try:
            document = json.loads(_read_text(path))
        except ValueError as exc:
            raise ConfigurationError(f"{str(path)!r} is not valid JSON: {exc}") from exc
        if not isinstance(document, list):
            raise ConfigurationError(
                f"{str(path)!r} must hold a JSON list of cedar entities, "
                f"not {type(document).__name__}"
            )
        return tuple(_entity_from_json(item, path) for item in document)

    def _origins(self, sources: tuple[tuple[Path, str], ...]) -> tuple[str, ...]:
        """Name the file each policy of the combined text came from.

        The combined parse knows the policies but not their files; a per-file parse knows the
        files but numbers the policies from zero each time. Counting per file and expanding
        the counts is what reconciles the two.

        Args:
            sources: The ``(path, text)`` pairs, in concatenation order.

        Returns:
            One file path per policy, positionally aligned with the combined text.

        Raises:
            ConfigurationError: If a file does not parse, named so the fault is findable.
        """
        origins: list[str] = []
        for path, text in sources:
            try:
                contributed = len(policy_annotations(text))
            except ConfigurationError as exc:
                raise ConfigurationError(f"{str(path)!r} is not valid cedar policy: {exc}") from exc
            origins.extend([str(path)] * contributed)
        return tuple(origins)

    def _validate_against(self, policies: str, schema: str) -> None:
        """Type-check the loaded bundle against its schema, refusing to wire an invalid one.

        Validation is reported, never raised, by Cedar — see
        :func:`~sentrykit.cedar.validate_policies`, which normalizes that. Turning a failure
        into a :class:`~sentrykit.errors.ConfigurationError` here is the point: a policy set
        that cannot possibly permit anything should stop a deployment at startup rather than
        deny every request for the rest of the process's life.

        Raises:
            ConfigurationError: If validation did not pass.
        """
        outcome = validate_policies(policies, schema)
        if outcome.passed:
            return
        raise ConfigurationError(
            f"policy source {self._name!r} failed cedar validation in "
            f"{str(self._path)!r}: {outcome.describe()}"
        )


def _derived_name(target: str) -> str:
    """Name a source after the directory it reads, for provenance and id namespacing.

    Args:
        target: The DSN target — a filesystem path, possibly relative or trailing-slashed.

    Returns:
        The final path component, or an empty string when the path has no usable one (a bare
        ``.`` or a drive root), in which case the caller falls back to the scheme.
    """
    resolved = Path(target.strip()).expanduser()
    for candidate in (resolved, resolved.resolve()):
        name = candidate.name
        if name and name not in {".", ".."}:
            return name
    return ""


def _combine(sources: tuple[tuple[Path, str], ...]) -> str:
    """Concatenate policy files with a newline between them.

    A newline, not an empty string: two files whose contents do not end in one would
    otherwise fuse the last policy of the first into the first policy of the second.
    """
    return "\n".join(text for _, text in sources)


def _read_text(path: Path) -> str:
    """Read a UTF-8 file, reporting an unreadable one as a configuration fault.

    Raises:
        ConfigurationError: If the file cannot be read or decoded.
    """
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigurationError(f"cannot read {str(path)!r}: {exc}") from exc


def _entity_from_json(raw: object, origin: Path) -> Entity:
    """Build one :class:`~sentrykit.cedar.Entity` from a Cedar entity-JSON object.

    Args:
        raw: One element of the entity document.
        origin: The file it came from, for the error message.

    Returns:
        The entity.

    Raises:
        ConfigurationError: If the object is not shaped like a Cedar entity.
    """
    if not isinstance(raw, dict):
        raise ConfigurationError(
            f"{str(origin)!r} holds a {type(raw).__name__} where a cedar entity was expected"
        )
    attributes = raw.get("attrs", raw.get("attributes", {})) or {}
    if not isinstance(attributes, dict):
        raise ConfigurationError(f"{str(origin)!r}: entity 'attrs' must be an object")
    parents = raw.get("parents") or []
    if not isinstance(parents, list):
        raise ConfigurationError(f"{str(origin)!r}: entity 'parents' must be a list")
    return Entity(
        uid=_ref_from_json(raw.get("uid"), origin),
        attributes={str(key): value for key, value in attributes.items()},
        parents=tuple(_ref_from_json(parent, origin) for parent in parents),
    )


def _ref_from_json(raw: object, origin: Path) -> EntityRef:
    """Read an entity reference in any of the three spellings Cedar JSON uses.

    The structured form, the ``__entity`` wrapper and the plain surface string all appear in
    hand-written entity files, and rejecting two of them would be pedantry with no upside.

    Raises:
        ConfigurationError: If the value is none of those.
    """
    if isinstance(raw, str):
        return EntityRef.parse(raw)
    if isinstance(raw, dict):
        inner = raw.get("__entity", raw)
        if isinstance(inner, dict):
            entity_type = inner.get("type")
            entity_id = inner.get("id")
            if isinstance(entity_type, str) and isinstance(entity_id, str):
                return EntityRef(entity_type, entity_id)
    raise ConfigurationError(
        f"{str(origin)!r} holds {raw!r} where a cedar entity reference was expected"
    )
