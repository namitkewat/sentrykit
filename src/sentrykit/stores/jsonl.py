"""The append-only JSONL audit sink — one record per line, one writer per file.

Every design choice here was forced by measurement on the ``win-64`` platform this repo
targets, rather than chosen for taste:

* **``newline="\\n"``, always.** Default text-mode append writes ``\\r\\n`` on Windows. A hash
  chain is over bytes, so left at the default the same record would hash differently per
  platform and an external verifier would disagree with the writer.
* **One handle, one lock.** ``open(path, "a")`` per write is *not* atomic on Windows — the CRT
  emulates append as seek-to-end plus write, and the pair races. Measured: 8 threads x 200
  records produced 1346 of 1600 lines, three of them malformed. One shared handle behind a
  ``threading.Lock`` produced 1600 of 1600.
* **Single writer per file.** Not a shortcut: ``record_hash`` depends on ``prev_hash``, so a
  writer must know the file's tail before it can build the next record, and that state cannot
  be shared across processes without a distributed lock. Concurrent writers get separate files
  (or a fan-out composite); multi-process durability is what a database-backed sink is for.
* **Flush always, fsync on request.** ``fsync`` costs 3.71 ms per record against 0.007 ms for
  ``flush`` alone. Paying that on every authorization decision to defend against machine
  crash — process crash is already covered by ``flush`` — is the wrong default for a
  pre-action gate, so it lives behind ``jsonl://path?fsync=true``.

This sink does **not** chain records. :class:`~sentrykit.audit.AuditTrail` does that; the sink
receives an already-chained, already-masked record and persists it. :meth:`JsonlAuditSink.tail_hash`
exists so a trail can pick a chain back up across a process restart.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Final

from sentrykit.audit import GENESIS_HASH, AuthzAuditRecord, ChainVerdict, verify_chain
from sentrykit.errors import AuditUnavailable, ConfigurationError
from sentrykit.registry import DSN, register_audit_sink
from sentrykit.stores.base import AuditWindow

__all__ = ["JsonlAuditSink"]

_LOGGER: Final = logging.getLogger("sentrykit.stores.jsonl")

_TAIL_CHUNK: Final = 4096
"""How many bytes to read back from the end at a time when recovering the tail record."""


@register_audit_sink("jsonl")
class JsonlAuditSink:
    """One JSON object per line, appended to a file that is never rewritten.

    Args:
        path: The log file. Parent directories are created if they are missing.
        name: Short name for this sink, used in fan-out error reporting.
        fsync: Whether to force the bytes to disk after every record. Off by default; see the
            module docstring for the measured cost.

    Raises:
        ConfigurationError: If the file cannot be opened, or if it already exists and its last
            line is not a readable audit record — a chain cannot be resumed from a tail that
            cannot be read, and guessing at it would silently start a second chain in one file.

    Example:
        ```python
        with JsonlAuditSink("./audit.jsonl") as sink:
            trail = AuditTrail(sink)
        ```
    """

    __slots__ = (
        "_closed",
        "_fsync",
        "_handle",
        "_lock",
        "_name",
        "_path",
        "_tail_hash",
        "_tail_sequence",
    )

    def __init__(self, path: str | Path, *, name: str = "jsonl", fsync: bool = False) -> None:
        self._path = Path(path)
        self._name = name
        self._fsync = fsync
        self._lock = threading.Lock()
        self._closed = False
        self._tail_hash: str = GENESIS_HASH
        self._tail_sequence = -1

        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ConfigurationError(
                f"audit sink {self._name!r} cannot create {str(self._path.parent)!r}: {exc}"
            ) from exc

        self._resume()

        try:
            # newline="\n" is a correctness requirement, not a style choice: the chain hashes
            # bytes, and the default would write \r\n here and \n on Linux.
            self._handle: IO[str] = self._path.open("a", encoding="utf-8", newline="\n")
        except OSError as exc:
            raise ConfigurationError(
                f"audit sink {self._name!r} cannot open {str(self._path)!r}: {exc}"
            ) from exc

    @classmethod
    def from_dsn(cls, dsn: DSN) -> JsonlAuditSink:
        """Build from ``jsonl://<path>?fsync=true``.

        Args:
            dsn: The parsed address.

        Returns:
            The sink.

        Raises:
            ConfigurationError: If the DSN names no path, or ``fsync`` is not a boolean.
        """
        if not dsn.target.strip():
            raise ConfigurationError(f"{dsn.raw!r} names no audit log file")
        return cls(dsn.target, name=dsn.scheme, fsync=dsn.flag("fsync", False))

    @property
    def name(self) -> str:
        """Short name for this sink, used in fan-out error reporting."""
        return self._name

    @property
    def path(self) -> Path:
        """The file this sink appends to."""
        return self._path

    def tail_sequence(self) -> int:
        """The sequence number of the last record in the log, or ``-1`` when it is empty.

        The companion to :meth:`tail_hash`: together they are everything an
        :class:`~sentrykit.audit.AuditTrail` needs to continue an existing chain instead of
        restarting one at sequence zero in the middle of a file — which
        :func:`~sentrykit.audit.verify_chain` would read as a deleted record, not a restart.
        """
        return self._tail_sequence

    def tail_hash(self) -> str:
        """The last record's hash, or :data:`~sentrykit.audit.GENESIS_HASH` for an empty log.

        Recovered from the file at construction and kept current on every write, so it is
        correct across a process restart without re-reading the log.
        """
        return self._tail_hash

    def write(self, record: AuthzAuditRecord) -> None:
        """Append one record, already masked and already chained.

        Args:
            record: The record to persist.

        Raises:
            AuditUnavailable: If the record could not be durably appended — the sink is
                closed, the disk is full, or the record does not render to JSON. Under
                ``fail_mode="closed"`` the governed call is then refused: an action nobody can
                prove happened is an action that should not have happened.
        """
        with self._lock:
            if self._closed:
                raise AuditUnavailable(self._name, f"the sink over {str(self._path)!r} is closed")
            try:
                line = json.dumps(
                    record.model_dump(mode="json"),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                self._handle.write(line + "\n")
                self._handle.flush()
                if self._fsync:
                    os.fsync(self._handle.fileno())
            except (OSError, TypeError, ValueError) as exc:
                raise AuditUnavailable(self._name, str(exc)) from exc

            if record.record_hash:
                self._tail_hash = record.record_hash
            self._tail_sequence = max(self._tail_sequence, record.sequence)

    def query(self, window: AuditWindow) -> Iterator[AuthzAuditRecord]:
        """Read back the records matching ``window``, oldest first.

        Re-reads the file lazily rather than holding an index, so a long log costs one line
        at a time and a caller with a ``limit`` stops paying at the limit. Reading a file this
        sink is still appending to is safe — confirmed on Windows, no sharing violation.

        Args:
            window: The filter.

        Returns:
            An iterator over the matching records.

        Raises:
            AuditUnavailable: If the log cannot be read, or holds a line that is not a
                readable audit record. A corrupt line is tamper evidence, so it is surfaced
                rather than skipped past.
        """
        return self._replay(window)

    def verify(self) -> ChainVerdict:
        """Re-read the whole file and verify the hash chain.

        Returns:
            The verdict, naming the first record that fails. A line that will not parse is
            itself a broken chain rather than an exception: :meth:`verify` is what an operator
            runs *because* they suspect the file, so it has to survive a damaged one.

        Raises:
            AuditUnavailable: If the file cannot be read at all.
        """
        records: list[AuthzAuditRecord] = []
        for position, line in enumerate(self._lines()):
            try:
                records.append(AuthzAuditRecord.model_validate_json(line))
            except ValueError:
                return ChainVerdict(
                    ok=False,
                    broken_at=position,
                    reason=f"line {position + 1} is not a readable audit record",
                )
        return verify_chain(records)

    def close(self) -> None:
        """Flush and release the file handle. Idempotent."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._handle.flush()
                self._handle.close()
            except OSError as exc:  # pragma: no cover - closing a flushed handle rarely fails
                _LOGGER.warning(
                    "Audit sink failed to close cleanly",
                    extra={"sink": self._name, "path": str(self._path), "error": str(exc)},
                )

    def __enter__(self) -> JsonlAuditSink:
        """Return the sink, so it can be used as a context manager."""
        return self

    def __exit__(self, *exc: object) -> None:
        """Close the sink on the way out of the block."""
        self.close()

    def _resume(self) -> None:
        """Recover the chain tail and the next sequence number from an existing file.

        Raises:
            ConfigurationError: If the file exists but its last line cannot be read as an
                audit record.
        """
        if not self._path.is_file():
            return
        try:
            last = _last_line(self._path)
        except OSError as exc:
            raise ConfigurationError(
                f"audit sink {self._name!r} cannot read {str(self._path)!r}: {exc}"
            ) from exc
        if last is None:
            return
        try:
            record = AuthzAuditRecord.model_validate_json(last)
        except ValueError as exc:
            raise ConfigurationError(
                f"audit sink {self._name!r} cannot resume the chain in {str(self._path)!r}: "
                f"its last line is not a readable audit record ({exc})"
            ) from exc
        self._tail_hash = record.record_hash or GENESIS_HASH
        self._tail_sequence = record.sequence
        _LOGGER.debug(
            "Resumed an existing audit chain",
            extra={
                "sink": self._name,
                "path": str(self._path),
                "sequence": self._tail_sequence,
                "tail_hash": self._tail_hash,
            },
        )

    def _replay(self, window: AuditWindow) -> Iterator[AuthzAuditRecord]:
        """Yield the records matching ``window``, stopping at its limit."""
        yielded = 0
        for position, line in enumerate(self._lines()):
            try:
                record = AuthzAuditRecord.model_validate_json(line)
            except ValueError as exc:
                raise AuditUnavailable(
                    self._name,
                    f"line {position + 1} of {str(self._path)!r} is not a readable "
                    f"audit record: {exc}",
                ) from exc
            if not window.matches(record):
                continue
            yield record
            yielded += 1
            if window.limit is not None and yielded >= window.limit:
                return

    def _lines(self) -> Iterator[str]:
        """Yield the non-empty lines of the log, oldest first.

        Raises:
            AuditUnavailable: If the file cannot be read.
        """
        if not self._path.is_file():
            return
        try:
            with self._path.open("r", encoding="utf-8", newline="") as handle:
                for line in handle:
                    stripped = line.strip()
                    if stripped:
                        yield stripped
        except (OSError, UnicodeDecodeError) as exc:
            raise AuditUnavailable(self._name, f"cannot read {str(self._path)!r}: {exc}") from exc


def _last_line(path: Path) -> str | None:
    """Return the last non-empty line of a file without reading all of it.

    An audit log only grows, so a linear scan at every process start would get slower for the
    lifetime of the deployment. Reading backwards in chunks keeps the cost proportional to one
    record. The last element of a chunk that ends at EOF is always a complete line — only the
    *first* element can be truncated — so the window only has to grow while a chunk holds
    fewer than two lines.

    Args:
        path: The file to read.

    Returns:
        The last non-empty line, or ``None`` if the file holds none.

    Raises:
        OSError: If the file cannot be read.
    """
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        if size == 0:
            return None
        window = 0
        while True:
            window = min(size, window + _TAIL_CHUNK)
            handle.seek(size - window)
            lines = [part.strip() for part in handle.read(window).split(b"\n") if part.strip()]
            if lines and (len(lines) > 1 or window == size):
                return lines[-1].decode("utf-8")
            if window == size:
                return None
