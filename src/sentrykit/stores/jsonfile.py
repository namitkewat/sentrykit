"""A durable grant store: one JSON document, replaced atomically, re-read when it changes.

``sentrykit grant`` in one shell and ``sentrykit revoke`` in another are two processes, and
the only shipped grant store before this one — :class:`~sentrykit.stores.memory.InMemoryGrantStore`
— dies with the process that made the grant. Every CLI invocation therefore started against
an empty store and refused *itself*, because the admin surface resolves its operator through
:meth:`~sentrykit.stores.base.GrantStore.get_principal` and fails closed when the store has
never heard of them. Architecture §4 calls the grant store "the admin surface's only write
target"; this module is the write target that survives the process.

Four decisions, and none of them is taste:

* **Persistence subclasses the in-memory semantics; it does not restate them.**
  :class:`JsonFileGrantStore` extends :class:`~sentrykit.stores.memory.InMemoryGrantStore`, so
  materialization — expiry and revocation excluded, roles as ``Role::"…"`` parent edges,
  attributes, per-action constraints — is *the same code*. A second hand-written materializer
  is the one bug this shape cannot have.
* **The whole document is replaced, never edited in place.** A temp file in the same
  directory is written, flushed, ``fsync``-ed and then renamed over the target;
  :meth:`~pathlib.Path.replace` is ``os.replace``, which is atomic on Windows and POSIX alike.
  A write that dies halfway leaves the previous grants untouched, which is the property a
  store of "who may do what" has to have. Unlike
  :class:`~sentrykit.stores.jsonl.JsonlAuditSink`, ``fsync`` is unconditional here: a grant is
  a rare administrative event, not a per-decision cost, so ADR-013's 3.71 ms measurement buys
  durability where it is cheap.
* **Records round-trip through pydantic with ``exclude_unset=True``.** Not an optimization —
  a correctness requirement. :attr:`~sentrykit.constraints.ArgumentConstraint.has_default`
  is derived from ``model_fields_set``, so a full ``model_dump`` writes ``"default": null``
  for a constraint that configured no default, and reading it back would make the store
  inject ``None`` into every call that omitted the argument. Dumping only what was set
  preserves ``model_fields_set`` exactly.
* **Reads are gated on a stat, not on a parse.** :meth:`JsonFileGrantStore.get_principal` is
  on the hot path of every governed call, so the file is re-read only when its
  ``st_mtime_ns`` **or** ``st_size`` differs from the pair recorded at the last read.

**One writing process at a time.** Stated as plainly as ADR-013 states it for the audit sink:
this is a store for a single-node deployment, a development loop, and the CLI. Two processes
writing concurrently can lose a grant, because each replaces the whole document with its own
view of it and no lock is taken — ``fcntl`` does not exist on Windows and a cross-platform
lock file would be a distributed-locking protocol wearing a disguise. Readers are safe against
any number of writers: they only ever observe a completely written document. A deployment that
needs concurrent writers should put a real database behind the same Protocol.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Final, NamedTuple, TypeAlias
from uuid import uuid4

from sentrykit.cedar import Entity, EntityRef
from sentrykit.context import Principal
from sentrykit.errors import ConfigurationError
from sentrykit.registry import DSN, register_grant_store
from sentrykit.stores.base import GrantRecord, GrantSpec
from sentrykit.stores.memory import InMemoryGrantStore

__all__ = ["JsonFileGrantStore"]

FORMAT_VERSION: Final = 1
"""Version stamped into every document, and the only version this reader accepts.

Refusing an unknown version is the same instinct as refusing corrupt JSON: a newer sentrykit
may write a field this one would drop on the next rewrite, and silently rewriting a document
you only half understood loses grants.
"""

_Stamp: TypeAlias = tuple[int, int]
"""``(st_mtime_ns, st_size)`` — the pair the refresh gate compares.

Both halves, because neither is trustworthy alone: ``st_mtime_ns`` has coarse resolution on
some filesystems (two writes inside one tick look identical), and ``st_size`` collides
whenever an edit happens to preserve the length. Two independent quantities agreeing by
accident is far rarer than either doing so.
"""


class _Document(NamedTuple):
    """What one file holds, decoded."""

    grants: tuple[GrantRecord, ...]
    entities: tuple[Entity, ...]


class _State(NamedTuple):
    """A snapshot of the inherited in-memory state, taken so a failed write can be undone."""

    grants: dict[str, GrantRecord]
    by_principal: dict[EntityRef, list[str]]
    entities: dict[EntityRef, Entity]


@register_grant_store("jsonfile")
class JsonFileGrantStore(InMemoryGrantStore):
    """Grants held in one JSON file, shared between processes and durable across restarts.

    Everything :class:`~sentrykit.stores.memory.InMemoryGrantStore` does, plus a file. Writes
    (:meth:`grant`, :meth:`revoke`, :meth:`add_entity`) replace the document atomically; reads
    (:meth:`get_principal`, :meth:`grants_for`, :meth:`entities`) re-read it first, but only
    when a ``stat`` says it changed.

    A write is all-or-nothing in memory too: if the document cannot be replaced, the in-memory
    state is rolled back to what was last durable and the error is raised. A grant that did
    not reach the disk did not happen.

    A **missing file is not an error** — it is an empty store that creates the file, and any
    missing parent directories, on its first write, because ``sentrykit grant`` against a
    fresh deployment has to work. A file that exists and cannot be understood **is** an error:
    starting empty on unreadable JSON would silently discard an audit-relevant record set.

    **One writing process at a time**; see the module docstring for what that rules out.

    Args:
        path: The JSON document. Parent directories are created on the first write.
        name: Short name for this store, used for namespace routing and audit provenance.
        namespace: The namespace this store answers for, when a
            :class:`~sentrykit.stores.composite.CompositeGrantStore` routes by namespace
            rather than merging by precedence. ``None`` means it takes part in merging.

    Raises:
        ConfigurationError: If the file exists but cannot be read, parsed, or understood.

    Example:
        ```python
        store = JsonFileGrantStore("./var/grants.json")
        store.grant(GrantSpec(principal=EntityRef("User", "alice"), kind="role",
                              subject="support"))
        # another process, same file
        JsonFileGrantStore("./var/grants.json").get_principal("alice")
        ```
    """

    __slots__ = ("_closed", "_path", "_stamp")

    def __init__(
        self,
        path: str | Path,
        *,
        name: str = "jsonfile",
        namespace: str | None = None,
    ) -> None:
        super().__init__(name=name, namespace=namespace)
        self._path = Path(path)
        # ``None`` means "the file did not exist as of the last look", which is also the state
        # a fresh store starts in -- so a missing file costs one ``stat`` and no parse.
        self._stamp: _Stamp | None = None
        self._closed = False
        self._refresh()

    @classmethod
    def from_dsn(cls, dsn: DSN) -> JsonFileGrantStore:
        """Build from ``jsonfile://./var/grants.json?name=…&namespace=…``.

        Args:
            dsn: The parsed address. The target is the file path — never the namespace, unlike
                ``memory://tenant-a``, because a path is what this backend needs and guessing
                between the two would make ``jsonfile://grants.json`` mean something surprising.

        Returns:
            The store.

        Raises:
            ConfigurationError: If the DSN names no path, or the named file cannot be read.
        """
        if not dsn.target.strip():
            raise ConfigurationError(f"{dsn.raw!r} names no grant file")
        namespace = dsn.option("namespace") or None
        return cls(
            dsn.target,
            name=dsn.option("name") or namespace or dsn.scheme,
            namespace=namespace,
        )

    @property
    def path(self) -> Path:
        """The file this store persists to."""
        return self._path

    # --- the file ------------------------------------------------------------------------

    def reload(self) -> None:
        """Re-read the file, discarding the in-memory state.

        Unconditional, unlike the refresh every read performs: a caller reaches for this when
        they know something changed that a ``stat`` might not show, or to drop local state
        they no longer trust. A missing file reloads to an empty store — the file *is* the
        store.

        Raises:
            ConfigurationError: If the file exists but cannot be read or understood.
        """
        with self._lock:
            # Stat first, read second. A write landing between the two makes the recorded
            # stamp older than the content, so the next refresh re-reads needlessly; the
            # reverse order would record a newer stamp for older content and miss the update
            # entirely. Over-reading is a wasted parse, under-reading is a wrong decision.
            stamp = self._stat()
            self._install(_read_document(self._path, self.name), stamp)

    def flush(self) -> None:
        """Write the current state out, whether or not it changed.

        Every mutation already persists, so this exists for the case where the in-memory state
        was reached some other way — after a :meth:`reload` into a store a caller then wants
        re-stamped, or in a test.

        Raises:
            ConfigurationError: If the document cannot be written.
        """
        with self._lock:
            self._write()

    def close(self) -> None:
        """Refuse further writes. Idempotent.

        There is no handle to release: every mutation has already been flushed and renamed
        into place by the time it returns. This satisfies
        :class:`~sentrykit.stores.base.SupportsClose` so a host that closes every backend
        uniformly does not have to special-case this one, and it makes a write after teardown
        a loud error rather than a change nobody will find.
        """
        with self._lock:
            self._closed = True

    # --- writes --------------------------------------------------------------------------

    def grant(self, spec: GrantSpec, *, now: datetime | None = None) -> GrantRecord:
        """Confer a grant and persist the whole document.

        Refreshes first, so a grant made by another process is carried forward rather than
        overwritten — the document is replaced wholesale, so writing a stale view of it is
        how a concurrent grant would disappear.

        Args:
            spec: What to confer.
            now: The grant timestamp. Defaults to the current UTC time.

        Returns:
            The stored record, carrying the id needed to revoke it.

        Raises:
            ConfigurationError: If the spec is inconsistent, the store is closed, or the
                document could not be written — in which case the in-memory state is rolled
                back and nothing was granted.
        """
        with self._lock:
            self._writable()
            self._refresh()
            rollback = self._snapshot()
            record = super().grant(spec, now=now)
            self._persist(rollback)
            return record

    def revoke(
        self,
        grant_id: str,
        *,
        revoked_by: str | None = None,
        reason: str | None = None,
        now: datetime | None = None,
    ) -> GrantRecord:
        """Withdraw a grant and persist the whole document.

        The record is marked, never deleted, so "who had what, when" survives in the file as
        well as in memory.

        Args:
            grant_id: The id returned by :meth:`grant`.
            revoked_by: The actor withdrawing it.
            reason: Why.
            now: The revocation timestamp. Defaults to the current UTC time.

        Returns:
            The updated record.

        Raises:
            ConfigurationError: If no such grant exists, the store is closed, or the document
                could not be written.
        """
        with self._lock:
            self._writable()
            self._refresh()
            rollback = self._snapshot()
            record = super().revoke(grant_id, revoked_by=revoked_by, reason=reason, now=now)
            # Revoking an already-revoked grant returns it unchanged. Rewriting the file for
            # that would churn the mtime and make every other process re-parse for nothing.
            if record is not rollback.grants.get(grant_id):
                self._persist(rollback)
            return record

    def add_entity(self, entity: Entity) -> None:
        """Seed one node of the stable entity graph and persist the whole document.

        Args:
            entity: The node — a role, team, or project a parent edge points at. Principals do
                not belong here; they are materialized per request.

        Raises:
            ConfigurationError: If the store is closed, or the document could not be written.
        """
        with self._lock:
            self._writable()
            self._refresh()
            rollback = self._snapshot()
            super().add_entity(entity)
            self._persist(rollback)

    # --- reads ---------------------------------------------------------------------------

    def get_principal(
        self,
        principal: str | EntityRef,
        *,
        now: datetime | None = None,
    ) -> Principal | None:
        """Materialize a principal from their active grants, refreshing from disk first.

        The refresh is what makes ``sentrykit grant`` in one process visible to a decision in
        another without either of them coordinating. It costs one ``stat`` when nothing
        changed, which is what keeps this method on the hot path of every governed call.

        Args:
            principal: The principal id (assumed type ``User``) or a full reference.
            now: The moment to evaluate expiries against. Defaults to the current UTC time.

        Returns:
            The principal, or ``None`` when the store holds neither a grant nor a seeded
            entity for them.

        Raises:
            ConfigurationError: If the file changed into something that cannot be understood.
        """
        with self._lock:
            self._refresh()
            return super().get_principal(principal, now=now)

    def grants_for(
        self,
        principal: str | EntityRef,
        *,
        include_inactive: bool = False,
    ) -> tuple[GrantRecord, ...]:
        """List the grants held by ``principal``, oldest first, refreshing from disk first.

        Args:
            principal: The principal id or reference.
            include_inactive: Whether to include revoked and expired grants.

        Returns:
            The grants, in the order they were made.

        Raises:
            ConfigurationError: If the file changed into something that cannot be understood.
        """
        with self._lock:
            self._refresh()
            return super().grants_for(principal, include_inactive=include_inactive)

    def entities(self) -> tuple[Entity, ...]:
        """Return the stable entities this store contributes, refreshing from disk first.

        Returns:
            The seeded nodes and the nodes the grant edges point at, exactly as the in-memory
            store derives them.

        Raises:
            ConfigurationError: If the file changed into something that cannot be understood.
        """
        with self._lock:
            self._refresh()
            return super().entities()

    # --- internals -----------------------------------------------------------------------

    def _writable(self) -> None:
        """Refuse a mutation on a closed store.

        Raises:
            ConfigurationError: If :meth:`close` has been called.
        """
        if self._closed:
            raise ConfigurationError(
                f"grant store {self.name!r} over {str(self._path)!r} is closed"
            )

    def _refresh(self) -> None:
        """Re-read the file if — and only if — its stamp moved since the last read.

        Raises:
            ConfigurationError: If the file cannot be read or understood.
        """
        stamp = self._stat()
        if stamp == self._stamp:
            return
        self._install(_read_document(self._path, self.name), stamp)

    def _stat(self) -> _Stamp | None:
        """Return the file's ``(st_mtime_ns, st_size)``, or ``None`` when it does not exist.

        Raises:
            ConfigurationError: If the path exists but cannot be stat-ed.
        """
        try:
            info = self._path.stat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ConfigurationError(
                f"grant store {self.name!r} cannot inspect {str(self._path)!r}: {exc}"
            ) from exc
        return (info.st_mtime_ns, info.st_size)

    def _install(self, document: _Document, stamp: _Stamp | None) -> None:
        """Replace the inherited in-memory state with what the file holds.

        Writes straight into the base class's own structures on purpose: reusing its
        materializer means reusing the structures it materializes *from*, and a parallel copy
        kept in this subclass would be the drift the whole design exists to prevent.

        Args:
            document: The decoded file.
            stamp: The stamp to record, taken *before* the read.

        Raises:
            ConfigurationError: If the file lists one grant id twice, which would make
                ``grants_for`` report it twice and ``revoke`` ambiguous.
        """
        self._grants.clear()
        self._by_principal.clear()
        self._entities.clear()
        for record in document.grants:
            if record.id in self._grants:
                raise ConfigurationError(
                    f"grant store {self.name!r} cannot read {str(self._path)!r}: "
                    f"it lists grant id {record.id!r} more than once"
                )
            self._grants[record.id] = record
            self._by_principal.setdefault(record.spec.principal, []).append(record.id)
        for entity in document.entities:
            self._entities[entity.uid] = entity
        self._stamp = stamp

    def _snapshot(self) -> _State:
        """Copy the in-memory state so a failed write can be undone.

        One shallow copy per structure. The write already serializes every grant, so an O(n)
        copy alongside it is not a new cost — and it is what lets a store that could not
        persist a grant report that nothing was granted, rather than carrying a change no
        restart would reproduce.
        """
        return _State(
            grants=dict(self._grants),
            by_principal={key: list(value) for key, value in self._by_principal.items()},
            entities=dict(self._entities),
        )

    def _persist(self, rollback: _State) -> None:
        """Write the document, restoring ``rollback`` if it could not be replaced.

        Raises:
            ConfigurationError: If the document could not be written.
        """
        try:
            self._write()
        except ConfigurationError:
            self._grants.clear()
            self._grants.update(rollback.grants)
            self._by_principal.clear()
            self._by_principal.update(rollback.by_principal)
            self._entities.clear()
            self._entities.update(rollback.entities)
            raise

    def _write(self) -> None:
        """Serialize the state and replace the file with it atomically.

        Raises:
            ConfigurationError: If the directory cannot be created, the document cannot be
                rendered, or the file cannot be written or replaced.
        """
        payload = {
            "version": FORMAT_VERSION,
            # Recorded for whoever opens the file, and ignored on read: the store's name is
            # wiring, not data, so a file moved between two deployments keeps neither name.
            "name": self.name,
            # ``exclude_unset`` is load-bearing -- see the module docstring on ``has_default``.
            "grants": [
                record.model_dump(mode="json", exclude_unset=True)
                for record in self._grants.values()
            ],
            # Cedar-coerced attributes, because that is the only form that ever reaches a
            # decision: ``as_json`` is what the engine would have been handed anyway.
            "entities": [entity.as_json() for entity in self._entities.values()],
        }
        try:
            text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(
                f"grant store {self.name!r} cannot render {str(self._path)!r}: {exc}"
            ) from exc

        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ConfigurationError(
                f"grant store {self.name!r} cannot create {str(self._path.parent)!r}: {exc}"
            ) from exc

        # Same directory as the target, so the rename stays within one filesystem and is
        # therefore atomic. The pid and a random suffix keep two writers from colliding on the
        # temp name even though they are not allowed to collide on the document.
        temp = self._path.with_name(f"{self._path.name}.{os.getpid()}-{uuid4().hex[:8]}.tmp")
        try:
            # newline="\n" for the same reason ADR-013 pins it in the audit sink: text mode
            # writes \r\n on Windows, and a file this library both writes and reads should not
            # differ byte for byte per platform.
            with temp.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            # ``Path.replace`` is ``os.replace``: atomic on Windows and POSIX alike, so a
            # reader sees either the whole previous document or the whole new one.
            temp.replace(self._path)
        except OSError as exc:
            raise ConfigurationError(
                f"grant store {self.name!r} cannot write {str(self._path)!r}: {exc}"
            ) from exc
        finally:
            # A no-op once the replace succeeded; the point is the path where it did not.
            temp.unlink(missing_ok=True)

        self._stamp = self._stat()


def _read_document(path: Path, name: str) -> _Document:
    """Decode the document at ``path``.

    A module-level function rather than a method because it is the *parse step*: the refresh
    gate's whole claim is that this does not run on an unchanged file, and a seam a test can
    count calls through is what keeps that claim honest.

    Args:
        path: The file.
        name: The store's name, for error messages.

    Returns:
        The decoded grants and seeded entities. A missing or empty file decodes to nothing —
        an empty store that will create the file on its first write. A zero-byte file is
        treated the same way: this store never truncates its target (it replaces it), so an
        empty file is something outside sentrykit made, and the friendly reading of ``touch``
        costs nothing because there are no records in it to discard.

    Raises:
        ConfigurationError: If the file exists and cannot be read, parsed, or understood.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return _Document((), ())
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigurationError(f"grant store {name!r} cannot read {str(path)!r}: {exc}") from exc
    if not text.strip():
        return _Document((), ())

    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise ConfigurationError(f"grant store {name!r} cannot parse {str(path)!r}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError(
            f"grant store {name!r} cannot read {str(path)!r}: its top level is a "
            f"{type(payload).__name__}, not a JSON object"
        )

    version = payload.get("version")
    if version != FORMAT_VERSION:
        raise ConfigurationError(
            f"grant store {name!r} cannot read {str(path)!r}: it declares format version "
            f"{version!r}, and this sentrykit reads version {FORMAT_VERSION}"
        )

    return _Document(
        grants=tuple(_decode_grants(payload.get("grants", []), path, name)),
        entities=tuple(_decode_entities(payload.get("entities", []), path, name)),
    )


def _decode_grants(raw: object, path: Path, name: str) -> list[GrantRecord]:
    """Validate the ``grants`` array back into records.

    Straight through pydantic rather than field by field, because a
    :class:`~sentrykit.stores.base.GrantSpec` carries an
    :class:`~sentrykit.cedar.EntityRef` and an optional
    :class:`~sentrykit.constraints.ArgumentConstraint`, and hand-rolling those is how a store
    starts losing constraint data.

    Raises:
        ConfigurationError: If the array or any element is not a readable grant.
    """
    if not isinstance(raw, list):
        raise ConfigurationError(
            f"grant store {name!r} cannot read {str(path)!r}: 'grants' is a "
            f"{type(raw).__name__}, not a list"
        )
    records: list[GrantRecord] = []
    for position, entry in enumerate(raw, start=1):
        try:
            records.append(GrantRecord.model_validate(entry))
        except ValueError as exc:
            raise ConfigurationError(
                f"grant store {name!r} cannot read grant {position} of {str(path)!r}: {exc}"
            ) from exc
    return records


def _decode_entities(raw: object, path: Path, name: str) -> list[Entity]:
    """Rebuild the seeded entity graph from the ``entities`` array.

    :class:`~sentrykit.cedar.Entity` is a dataclass rather than a model, so this is the one
    place that reads JSON by hand — and it validates the shape rather than trusting it, since
    an entity with no uid would otherwise surface as a ``KeyError`` from inside a decision.

    Raises:
        ConfigurationError: If the array or any element is not a readable entity.
    """
    if not isinstance(raw, list):
        raise ConfigurationError(
            f"grant store {name!r} cannot read {str(path)!r}: 'entities' is a "
            f"{type(raw).__name__}, not a list"
        )
    entities: list[Entity] = []
    for position, entry in enumerate(raw, start=1):
        if not isinstance(entry, dict):
            raise ConfigurationError(
                f"grant store {name!r} cannot read entity {position} of {str(path)!r}: "
                f"it is a {type(entry).__name__}, not a JSON object"
            )
        entities.append(
            Entity(
                uid=_decode_ref(entry.get("uid"), position, path, name),
                attributes=_decode_attributes(entry.get("attrs"), position, path, name),
                parents=tuple(
                    _decode_ref(parent, position, path, name)
                    for parent in _decode_list(entry.get("parents"), position, path, name)
                ),
            )
        )
    return entities


def _decode_ref(raw: object, position: int, path: Path, name: str) -> EntityRef:
    """Read one ``{"type", "id"}`` object back into a reference.

    Raises:
        ConfigurationError: If it is not one.
    """
    if (
        not isinstance(raw, dict)
        or not isinstance(raw.get("type"), str)
        or not isinstance(raw.get("id"), str)
    ):
        raise ConfigurationError(
            f"grant store {name!r} cannot read entity {position} of {str(path)!r}: "
            f"{raw!r} is not a {{'type', 'id'}} entity reference"
        )
    return EntityRef(type=raw["type"], id=raw["id"])


def _decode_attributes(raw: object, position: int, path: Path, name: str) -> dict[str, object]:
    """Read an entity's ``attrs`` object, defaulting an absent one to empty.

    Raises:
        ConfigurationError: If it is present and is not an object.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigurationError(
            f"grant store {name!r} cannot read entity {position} of {str(path)!r}: "
            f"'attrs' is a {type(raw).__name__}, not a JSON object"
        )
    return {str(key): value for key, value in raw.items()}


def _decode_list(raw: object, position: int, path: Path, name: str) -> list[object]:
    """Read an entity's ``parents`` array, defaulting an absent one to empty.

    Raises:
        ConfigurationError: If it is present and is not an array.
    """
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ConfigurationError(
            f"grant store {name!r} cannot read entity {position} of {str(path)!r}: "
            f"'parents' is a {type(raw).__name__}, not a list"
        )
    return raw
