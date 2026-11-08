"""The engine the desk runs on, and the calls that bring it into existence and take it away.

The default is an in-memory SQLite database, because an example that leaves a file behind is
an example somebody has to clean up before they trust what it prints. Set
``SENTRYKIT_DEMO_DB`` to a path and the same schema is written there instead, which is what to
do when you want to look at the data with another tool.

**Why the in-memory engine is built the way it is.** SQLite gives each connection to
``:memory:`` its own private, empty database, and SQLAlchemy's default pool for a memory URL
hands a *different* connection to each thread. Left alone, the result is a desk that seeds
fine and then serves nothing: the thread that answers the request never sees the thread that
did the seeding. :class:`~sqlalchemy.pool.StaticPool` keeps exactly one connection and shares
it, and ``check_same_thread=False`` lets a thread that did not open it use it. Both are
required together — either one alone leaves a server reading an empty database — which is why
there is a test asserting the property rather than the configuration.

Sharing one connection has a second consequence, and it does not announce itself: the
connection is shared but it is not *concurrent*. ``check_same_thread=False`` removes
pysqlite's objection to another thread using it; it does not make two overlapping queries on
one cursor safe, and under a threaded server they interleave and one of them comes back
truncated or raises from inside the result loader. So :func:`session_scope` serializes work on
the shared connection. That costs an example nothing — the desk answers in microseconds — and
it is the difference between a demo that is correct under a web server and one that is
intermittently wrong in a way nobody reproduces on purpose.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Generator
from contextlib import AbstractContextManager, contextmanager, nullcontext
from pathlib import Path

from sqlalchemy import Engine, create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from examples.desk.models import Base, Tenant
from examples.desk.seed import seed_desk

DB_URL_ENV = "SENTRYKIT_DEMO_DB"
"""Environment variable naming a file to keep the desk in, instead of memory."""

IN_MEMORY_URL = "sqlite:///:memory:"
"""Where the desk lives when nobody has said otherwise."""

_lock = threading.Lock()
"""Guards engine creation and the decision to seed.

Not defensive habit: the whole reason the in-memory engine is configured for shared,
cross-thread access is that a threaded web server reaches it from several request threads at
once, and two of them racing to seed would leave the desk holding every row twice.
"""

_shared_connection = threading.RLock()
"""Serializes work on the one connection an in-memory desk consists of.

Re-entrant, so that a caller who opens :func:`session_scope` and then calls one of the query
functions from inside it is served rather than deadlocked.

Two locks is two chances to deadlock, so the order is fixed: whoever wants both takes this one
*first* and :data:`_lock` second. Nothing anywhere acquires them the other way round --
:func:`engine` and :func:`close_desk` take :data:`_lock` alone and never reach for this -- so
there is no cycle for two threads to meet in.
"""

_engine: Engine | None = None
_engine_url: str | None = None
_ensured_url: str | None = None
"""The URL this process has already created and seeded, so a repeat call costs nothing.

Every query in :mod:`examples.desk.queries` calls :func:`ensure_desk` first, which is what
makes the query surface usable straight after an import. Without this, each of those calls
would re-interrogate sixteen tables to be told they exist.
"""


def database_url() -> str:
    """Return the URL the desk will be opened at.

    Read from the environment on every call rather than captured at import, so that a test or
    an app that sets ``SENTRYKIT_DEMO_DB`` after importing this module still gets what it
    asked for — as long as it has not opened the engine yet.

    Returns:
        A SQLAlchemy URL: the in-memory one, or SQLite over the path in
        ``SENTRYKIT_DEMO_DB``.
    """
    configured = os.environ.get(DB_URL_ENV, "").strip()
    if not configured:
        return IN_MEMORY_URL
    return f"sqlite:///{Path(configured).expanduser()}"


def engine() -> Engine:
    """Return the process-wide engine, opening it on first use.

    One engine per process, cached, because the in-memory database *is* the connection the
    pool is holding: a second engine on the same URL would be a second, empty desk.

    Returns:
        The engine every session in this process is bound to.
    """
    global _engine, _engine_url
    with _lock:
        url = database_url()
        if _engine is not None and _engine_url == url:
            return _engine
        if _engine is not None:
            _engine.dispose()
        _engine = _create_engine(url)
        _engine_url = url
        return _engine


def _create_engine(url: str) -> Engine:
    """Build an engine for ``url``, with the SQLite settings the module docstring explains.

    Args:
        url: The SQLAlchemy URL to open.

    Returns:
        A configured engine. Nothing has been connected to yet.
    """
    # A file database needs its directory to exist first; SQLite will not create one.
    path = url.removeprefix("sqlite:///")
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        # The same cross-thread allowance as the memory case, stated rather than inherited
        # from a dialect default, so both configurations behave the same under a server.
        return create_engine(url, connect_args={"check_same_thread": False})
    return create_engine(
        url,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )


def _guard(bound: Engine) -> AbstractContextManager[object]:
    """Return whatever has to be held while using ``bound``.

    An in-memory desk is one connection, so work on it is serialized. A file desk has a real
    pool handing out a connection per caller and needs nothing.

    Args:
        bound: The engine about to be used.

    Returns:
        The lock to hold, or a context manager that holds nothing.
    """
    if bound.url.database == ":memory:":
        return _shared_connection
    return nullcontext()


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Yield a session, committing on a clean exit and rolling back on an exception.

    The raw seam, for anyone who wants to query the desk with something the function surface
    in :mod:`examples.desk.queries` does not cover.

    Spelled ``Generator[Session, None, None]`` rather than ``Iterator[Session]``, which
    current type checkers flag as deprecated under ``@contextmanager``, and in the
    three-argument form rather than ``Generator[Session]``, whose single-argument spelling
    needs type-parameter defaults that only exist from Python 3.13.

    Yields:
        A session bound to the process-wide engine.
    """
    bound = engine()
    with _guard(bound), Session(bound) as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise


def ensure_desk() -> None:
    """Create the schema and seed it, unless it is already there.

    Idempotent, and that is the whole contract: the second call does nothing and leaves
    exactly the rows the first one wrote. "Already there" is judged on the tenant table — the
    desk's own identity — so a half-written database from an interrupted run reseeds rather
    than being treated as complete.

    **Safe to call at import time**, which is how the example apps use it. It writes nothing
    when the desk is already seeded, it takes well under a second when it is not, and against
    the default in-memory URL it touches no file at all. The one thing it is not safe to do at
    import time is :func:`reset_desk`, which discards data another process may be reading.

    The "already done it" answer is remembered per URL for the life of the process, so a
    second call is free. That memory is about what *this* process did; a file database another
    process empties underneath it will not be noticed until :func:`close_desk`.
    """
    global _ensured_url
    bound = engine()
    with _lock:
        if _ensured_url == _engine_url:
            return
    with _guard(bound):
        Base.metadata.create_all(bound)
        with _lock, Session(bound) as session:
            if session.scalar(select(Tenant.id).limit(1)) is None:
                seed_desk(session)
                session.commit()
            _ensured_url = _engine_url


def reset_desk() -> None:
    """Drop the schema, rebuild it and seed it again.

    What a test wants between cases, and what an app wants when it has been poking at the
    data and would like the printed tables to match the documentation again. Deterministic, so
    calling it twice leaves the same rows as calling it once.
    """
    global _ensured_url
    bound = engine()
    with _guard(bound):
        Base.metadata.drop_all(bound)
        Base.metadata.create_all(bound)
        with _lock, Session(bound) as session:
            seed_desk(session)
            session.commit()
            _ensured_url = _engine_url


def close_desk() -> None:
    """Dispose of the engine and forget it, so the next call re-reads the environment.

    An in-memory desk ceases to exist at this point, because the pooled connection holding it
    is what is being closed. Exists so that a test can move the desk to a different URL
    mid-process, which is otherwise impossible with a cached engine.
    """
    global _engine, _engine_url, _ensured_url
    with _lock:
        if _engine is not None:
            _engine.dispose()
        _engine = None
        _engine_url = None
        _ensured_url = None
