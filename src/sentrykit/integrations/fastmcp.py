"""The MCP tool-server context provider — the model proposes, the policy decides.

Wire it once and every ``@protect``-ed tool on the server is governed by the principal the
call arrived for:

```python
from mcp.server.mcpserver import MCPServer
from sentrykit.decorator import protect
from sentrykit.integrations.fastmcp import protect_server

server = MCPServer("orders")


@server.tool()
@protect(action="order.read", resource='Order::"o-1"')
def read_order(order_id: str, limit: int = 10) -> dict[str, object]: ...


protect_server(server)
```

`protect_server` installs one :class:`SentrykitToolMiddleware`, which does two things and
nothing else: it establishes ambient context around every ``tools/call`` and releases it
after, and it filters every ``tools/list`` result down to the tools the caller may actually
invoke.

## What "FastMCP" means here

The name is the one the extra, the entry point and the docs commit to — ``sentrykit[fastmcp]``,
``fastmcp://``. What it is built against is **mcp 2.0**, where the ergonomic server class was
renamed `mcp.server.fastmcp.FastMCP` → :class:`mcp.server.mcpserver.MCPServer`. Nothing here
imports the standalone `fastmcp` distribution, which does not import against mcp 2.0 at all
(`dev-docs/notes/phase-4-research.md` §0). If you have installed it hoping to use this module,
you do not need it.

## Two refusals, two shapes, one reason

A refused tool call **never reaches the tool**. The middleware plans the call, and on a
refusal returns a :class:`~mcp.types.CallToolResult` carrying ``isError`` and the ``_authz``
envelope in its structured content, *without* calling the rest of the chain. That is the
positioning in architecture §8 made concrete: the side effect is refused before it happens,
and the model gets a structured reason it can act on instead of an opaque error string.

Returning the refusal rather than raising it is not a style choice. Research §3 measured all
three options against a live client:

| the middleware… | what the client sees |
| --- | --- |
| lets the error propagate | `isError`, and `structuredContent` is **`None`** — envelope gone |
| returns a plain `dict` | a `ValidationError` for the missing `resultType` — the connection dies |
| returns a `CallToolResult` | `isError`, `structuredContent={"_authz": …}` ✔ |

A ``tools/list`` result is the other way round: by the time the middleware sees it, it is an
already-serialized mapping that *does* carry its discriminator, so filtering rewrites it in
place.

## The manifest is filtered, and the filter is not the enforcement

See :mod:`sentrykit.integrations.tools` for the invariant and why it is written the way it is.
The short version: hiding a tool and refusing it are the same decision made twice, so a client
that skips ``tools/list`` and calls a hidden tool by name gets refused just the same.

## Finding the callable behind an advertised name

mcp 2.0 exposes no public accessor for a registered tool's underlying function, and the
manifest filter needs one in order to read its ``@protect`` metadata. :func:`registered_tools`
reads the server's tool manager **defensively** — any failure degrades to "no tools
discovered" rather than to an exception on a live dispatch — and every entry point here
accepts an explicit ``tools=`` mapping for a host that would rather not depend on that at all.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult

from sentrykit.errors import ConfigurationError
from sentrykit.integrations.base import (
    DEFAULT_PRINCIPAL_HEADER,
    DEFAULT_REQUEST_ID_HEADER,
    BaseContextProvider,
)
from sentrykit.registry import DSN, register_context_provider

__all__ = [
    "CALL_TOOL_METHOD",
    "LIST_TOOLS_METHOD",
    "FastMCPProvider",
    "SentrykitToolMiddleware",
    "protect_server",
    "registered_tools",
]

CALL_TOOL_METHOD: str = "tools/call"
"""The inbound method the middleware establishes context around."""

LIST_TOOLS_METHOD: str = "tools/list"
"""The inbound method whose result the middleware filters."""


@register_context_provider("fastmcp")
class FastMCPProvider(BaseContextProvider["ServerRequestContext[Any, Any]"]):
    """Establishes ambient context from an MCP request and renders refusals as tool results.

    Construction is inherited from :class:`~sentrykit.integrations.base.BaseContextProvider`;
    see there for ``identify``, ``grants``, ``environment`` and the header options. The
    channel defaults to ``agent`` rather than ``http``, so a policy written
    ``when { context.channel == "agent" }`` applies to every tool call without the server
    saying anything.

    ### Where the principal comes from

    ``read_header`` looks in two places, in order:

    1. **``ctx.meta``** — the ``_meta`` object on the request params. It is an open map, both
       ``Client.call_tool`` and ``Client.list_tools`` accept ``meta=``, and it is the only
       carrier that exists on *every* transport including stdio and in-memory. This is what
       makes the example server and the whole test suite drivable without a socket.
    2. **The transport request's headers**, when the transport has one. ``None`` on stdio.

    Either is enough for an example, a smoke test, or a server behind a gateway that has
    already authenticated the caller, and nowhere near enough for anything else. A real
    deployment passes ``identify=``, typically reaching for
    :func:`mcp.server.mcpserver.authenticated_principal`, which resolves the OAuth
    ``(client, issuer, subject)`` identity from the ambient access token.
    """

    __slots__ = ()

    @classmethod
    def from_dsn(cls, dsn: DSN) -> FastMCPProvider:
        """Build from ``fastmcp://`` — the registry's door, used by ``install()``.

        Args:
            dsn: The parsed address. Options: ``header`` (the ``_meta`` key, or header name,
                a principal id is read from), ``request_id_header``.

        Returns:
            The provider.
        """
        # ``or`` rather than the option's own default, so ``?header=`` with an empty value
        # falls back to the shipped name instead of wiring a provider that reads ``""``.
        return cls(
            principal_header=dsn.option("header") or DEFAULT_PRINCIPAL_HEADER,
            request_id_header=dsn.option("request_id_header") or DEFAULT_REQUEST_ID_HEADER,
            channel="agent",
        )

    @property
    def name(self) -> str:
        """``fastmcp``."""
        return "fastmcp"

    def narrow(self, request: object) -> ServerRequestContext[Any, Any]:
        """Check that ``request`` is an MCP server request context.

        Args:
            request: The object the boundary handed over.

        Returns:
            The same object, typed.

        Raises:
            ConfigurationError: If it is not a
                :class:`~mcp.server.context.ServerRequestContext` — which means this provider
                was wired to the wrong framework.
        """
        if isinstance(request, ServerRequestContext):
            return request
        actual = type(request)
        raise ConfigurationError(
            "the fastmcp context provider expects an mcp ServerRequestContext but was given "
            f"a {actual.__module__}.{actual.__qualname__}; it is wired to the wrong framework"
        )

    def read_header(self, request: ServerRequestContext[Any, Any], name: str) -> str | None:
        """Read one value from the request's ``_meta``, falling back to transport headers.

        Args:
            request: The MCP request context.
            name: The ``_meta`` key, or header name, to read. Matched case-insensitively
                against headers, exactly against ``_meta`` keys — ``_meta`` is an open map
                whose keys the client chooses, and quietly matching a near-miss there would
                be guessing at identity.

        Returns:
            The value, or ``None`` when neither carrier has it.
        """
        raise NotImplementedError

    def render_error(self, error: Exception) -> CallToolResult:
        """Render a sentrykit refusal as a failed tool result carrying the ``_authz`` envelope.

        The body is :func:`~sentrykit.integrations.base.error_payload`'s — byte-identical to
        what a FastAPI or Flask caller would receive for the same refusal, because a refusal
        should read the same whether the caller was a browser or a model.

        Args:
            error: A :class:`~sentrykit.errors.SentrykitError`.

        Returns:
            A :class:`~mcp.types.CallToolResult` with ``is_error`` set, the caller-facing
            reason as text content, and the whole payload as structured content.
        """
        raise NotImplementedError


def registered_tools(server: MCPServer) -> dict[str, Callable[..., object]]:
    """Map every tool registered on ``server`` to the callable behind it.

    mcp 2.0 has no public accessor for this — ``MCPServer._tool_manager`` is private, though
    the ``list_tools()`` it exposes is an ordinary method and each ``Tool`` carries ``.name``
    and ``.fn``. So this reads it defensively and **never raises**: if the internal shape ever
    changes, the result is an empty mapping, every tool reads as ungoverned-and-visible, and
    enforcement on dispatch is completely unaffected. Degrading the *manifest* is survivable;
    raising from inside a live ``tools/list`` is not.

    Args:
        server: The MCP server.

    Returns:
        Tool name → registered callable. Empty when the tools could not be read, with a
        warning logged.
    """
    raise NotImplementedError


class SentrykitToolMiddleware:
    """Server middleware that governs tool dispatch and filters the tool manifest.

    Implements :class:`mcp.server.context.ServerMiddleware`. Registered outermost-first on
    ``MCPServer.middleware``, it wraps *every* inbound message; everything that is neither
    ``tools/call`` nor ``tools/list`` passes straight through untouched.

    For a ``tools/call`` the lifecycle is the web providers' exactly: establish on the way in,
    release in a ``finally``. The release is not tidiness — a dispatch that kept the previous
    caller's principal would authorize the next model call as somebody else, which is the
    worst failure this library can have. `dev-docs/notes/phase-4-research.md` §1 measured it
    on this transport specifically.

    Args:
        server: The server whose tools are being governed, used to resolve an advertised tool
            name back to its callable for the manifest filter. Optional when ``tools`` is
            given.
        provider: The provider to establish with. Defaults to the one wired into the installed
            governor by ``install(context_provider=...)``, and failing that to a
            ``_meta``-identifying :class:`FastMCPProvider`.
        tools: An explicit tool name → callable mapping, for a host that would rather not rely
            on :func:`registered_tools`. Takes precedence over ``server`` when both are given.
        filter_manifest: Whether to filter ``tools/list``. Turning it off leaves enforcement
            completely intact — see :mod:`sentrykit.integrations.tools` — and is for a server
            that would rather advertise a stable manifest to every caller.
    """

    __slots__ = ("_filter_manifest", "_provider", "_server", "_tools")

    def __init__(
        self,
        server: MCPServer | None = None,
        *,
        provider: FastMCPProvider | None = None,
        tools: Mapping[str, Callable[..., object]] | None = None,
        filter_manifest: bool = True,
    ) -> None:
        raise NotImplementedError

    async def __call__(
        self, ctx: ServerRequestContext[Any, Any], call_next: CallNext
    ) -> HandlerResult:
        """Route one inbound message to the dispatch gate, the manifest filter, or neither.

        Args:
            ctx: The request context, carrying the raw method and params.
            call_next: The rest of the middleware chain.

        Returns:
            Whatever the chain returned, or a refusal built in place of it.
        """
        raise NotImplementedError

    async def dispatch(
        self, ctx: ServerRequestContext[Any, Any], call_next: CallNext
    ) -> HandlerResult:
        """Establish context for one ``tools/call``, run it, and release.

        A :class:`~sentrykit.errors.SentrykitError` raised by a protected tool is caught and
        rendered as a failed tool result rather than allowed to propagate, because a
        propagating error loses the ``_authz`` envelope (see the module docstring). Anything
        else the tool raises is the tool's business and passes through untouched.

        Args:
            ctx: The request context.
            call_next: The rest of the middleware chain.

        Returns:
            The tool's result, or the refusal.
        """
        raise NotImplementedError

    async def manifest(
        self, ctx: ServerRequestContext[Any, Any], call_next: CallNext
    ) -> HandlerResult:
        """Filter a ``tools/list`` result down to what this caller may invoke.

        The result arrives already serialized and carrying its own ``resultType``, so the
        ``tools`` array is rewritten in place and everything else — cache scope, TTL, the
        server's ``_meta`` — is left exactly as the server built it.

        An **unauthenticated** caller is shown nothing: with no principal there is no
        entitlement to reason about, and every one of those tools would refuse on dispatch.
        That is the same fail-closed rule as everywhere else, applied to the manifest.

        Args:
            ctx: The request context.
            call_next: The rest of the middleware chain.

        Returns:
            The result, with ``tools`` narrowed.
        """
        raise NotImplementedError


def protect_server(
    server: MCPServer,
    *,
    provider: FastMCPProvider | None = None,
    tools: Mapping[str, Callable[..., object]] | None = None,
    filter_manifest: bool = True,
) -> FastMCPProvider:
    """Wire sentrykit into ``server`` in one call.

    Appends one :class:`SentrykitToolMiddleware` to ``server.middleware``. Calling it twice on
    the same server is a no-op the second time, so a module that wires at import and a test
    that wires in a fixture cannot double-govern a dispatch.

    Args:
        server: The MCP server.
        provider: The provider to use. Defaults as for :class:`SentrykitToolMiddleware`.
        tools: An explicit tool name → callable mapping.
        filter_manifest: Whether to filter ``tools/list``.

    Returns:
        The provider that was wired, so a caller can hold on to it.
    """
    raise NotImplementedError
