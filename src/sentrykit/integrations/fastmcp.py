"""The MCP tool-server context provider — the model proposes, the policy decides.

Wire it once and every ``@protect``-ed tool on the server is governed by the principal the
call arrived for:

```python
from mcp.server.mcpserver import MCPServer
from sentrykit.integrations.fastmcp import governed_tool, protect_server

server = MCPServer("orders")


@governed_tool(server, action="order.read", resource='Order::"o-1"')
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
imports the standalone `fastmcp` distribution, which does not import against mcp 2.0 at all.
If you have installed it hoping to use this module, you do not need it.

## Register protected tools with `governed_tool`, and nothing else

This is the one sharp edge in the module, so it is stated plainly: **a `@protect`-ed callable
handed straight to `@server.tool()` will have its refusals swallowed.** mcp's `Tool.run` wraps
whatever the body raised in a `ToolError` and `MCPServer._handle_call_tool` turns that into a
`CallToolResult(isError=True)` with **no structured content**, so the caller gets the string
`"Error executing tool …"` and the `_authz` envelope is gone before any middleware can see it.
The gate still ran and the side effect was still refused — but the model is told nothing it can
act on.

:func:`governed_tool` is what closes that. It registers the tool behind two thin layers, each
solving one measured problem and neither of them optional:

* a :func:`~sentrykit.integrations.tools.proposable` shim, so an argument the principal's
  policy would supply is **advertised as omittable** and can actually be omitted. mcp validates
  a proposal against the advertised schema before the body runs, so without this a parameter
  with no Python default could never be filled in from a policy default; and
* a translator that catches :class:`~sentrykit.errors.SentrykitError` and re-raises it as an
  :class:`mcp.shared.exceptions.MCPError`, which is the **one** exception type
  `_handle_call_tool` re-raises rather than swallowing. That is what carries a refusal out of
  the tool body intact.

Both layers keep ``__wrapped__`` pointing at the protected callable, so the manifest filter
still finds its ``@protect`` metadata, and ``governed_tool`` hands the protected callable back
unchanged — registering a tool does not take a function away from the rest of the program.

## A refusal never reaches the tool, and the decision is made exactly once

The gate runs inside ``@protect``, before the body — so the side effect is refused before it
happens, which is architecture §8 made concrete. The refusal then travels out as a
:class:`_ToolRefusal` and the middleware renders it as a
:class:`~mcp.types.CallToolResult` carrying ``isError`` and the ``_authz`` envelope in its
structured content, so the model gets a structured reason it can act on instead of an opaque
error string.

Deciding it *here* instead — planning the call in the middleware ahead of ``call_next`` —
also works, and is not what this module does, because it decides every allowed call twice:
one allowed dispatch then writes **two** ``allowed`` audit records, and a library positioned
audit-first cannot have its own log double-count. It also forces the caller-facing envelope
to be *reconstructed* from the pre-flight plan, so ``defaults_applied`` describes a decision
the decorator had not made. Both problems disappear when the refusal is
carried out rather than predicted.

What the middleware still owns is the *rendering*, and that shape is not a style choice.
Measured against a live client, the three options differ:

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

import functools
import inspect
import logging
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Final

from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.mcpserver import MCPServer
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult, TextContent

from sentrykit.context import Channel
from sentrykit.decorator import protect, protected_meta
from sentrykit.envelope import current_recorder, last_envelope, narrowing_guidance
from sentrykit.errors import ConfigurationError, SentrykitError
from sentrykit.integrations.base import (
    DEFAULT_PRINCIPAL_HEADER,
    DEFAULT_REQUEST_ID_HEADER,
    STATUS_PHRASES,
    BaseContextProvider,
    EnvironmentFactory,
    Identify,
    reason_for,
)
from sentrykit.integrations.tools import permitted_tools, proposable
from sentrykit.registry import DSN, register_context_provider
from sentrykit.stores.base import GrantStore

__all__ = [
    "CALL_TOOL_METHOD",
    "LIST_TOOLS_METHOD",
    "NARROWED_ARGUMENTS_META_KEY",
    "NARROWED_META_KEY",
    "FastMCPProvider",
    "SentrykitToolMiddleware",
    "governed_tool",
    "protect_server",
    "registered_tools",
]

_LOGGER: Final = logging.getLogger("sentrykit.integrations.fastmcp")

CALL_TOOL_METHOD: str = "tools/call"
"""The inbound method the middleware establishes context around."""

LIST_TOOLS_METHOD: str = "tools/list"
"""The inbound method whose result the middleware filters."""

_REFUSAL_CODE: Final = -32000
"""JSON-RPC code on the exception a refusal travels out of a tool body in.

Inside the implementation-defined server range, and never actually serialized: the middleware
unwraps the refusal and renders it as a tool result before it can reach the wire.
"""


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

    def __init__(
        self,
        *,
        identify: Identify[ServerRequestContext[Any, Any]] | None = None,
        grants: GrantStore | None = None,
        environment: EnvironmentFactory[ServerRequestContext[Any, Any]] | None = None,
        principal_header: str = DEFAULT_PRINCIPAL_HEADER,
        request_id_header: str = DEFAULT_REQUEST_ID_HEADER,
        channel: Channel = "agent",
    ) -> None:
        """Construct as :class:`~sentrykit.integrations.base.BaseContextProvider`, but agentic.

        Every parameter is the base class's, with the same meaning; the one difference is the
        ``channel`` default. It is pinned here rather than left to the base because a provider
        that documented ``agent`` and established ``http`` would silently fail every policy
        written ``when { context.channel == "agent" }`` — and it would fail them *open*
        relative to what the author intended, which is the wrong direction to be wrong in.

        Args:
            identify: The app's auth → identity callback.
            grants: Where a principal id is materialized.
            environment: Extra Cedar request context per request.
            principal_header: The ``_meta`` key, or header name, the default ``identify``
                reads.
            request_id_header: Where an incoming correlation id is taken from.
            channel: The channel established for every request.
        """
        super().__init__(
            identify=identify,
            grants=grants,
            environment=environment,
            principal_header=principal_header,
            request_id_header=request_id_header,
            channel=channel,
        )

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
        meta = getattr(request, "meta", None)
        if isinstance(meta, Mapping):
            carried = _as_header_value(meta.get(name))
            if carried is not None:
                return carried
        # ``ctx.request`` is ``None`` on stdio and on the in-memory transport, and the
        # transport's own request object on HTTP. Reached through ``getattr`` rather than an
        # import so this module stays independent of which transport mcp was built against.
        headers = getattr(getattr(request, "request", None), "headers", None)
        return _read_case_insensitively(headers, name) if headers is not None else None

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
        status, body = self.error_response(error)
        detail = body.get("detail")
        # The text content is what a model reads if it never looks at the structured half, so
        # it carries the same sentence a browser would have been shown. At ``verbosity="off"``
        # there is no reason to give, and the status phrase is all a caller is owed.
        text = detail if isinstance(detail, str) else STATUS_PHRASES.get(status, "Error")
        return CallToolResult(
            content=[TextContent(type="text", text=text)],
            structured_content=body,
            is_error=True,
        )


def _as_header_value(value: object) -> str | None:
    """Coerce one ``_meta`` value to a header string, or refuse to guess.

    ``_meta`` is an open map, so a client may put anything under the key a provider reads.
    A scalar is coerced — a principal id serialized as a number is still a principal id — but
    a mapping or a sequence is *not* stringified: ``"{'sub': 'alice'}"`` is not an identity,
    and inventing one from a structure nobody agreed on is exactly the guess that
    :meth:`FastMCPProvider.read_header` exists to avoid.

    Args:
        value: Whatever was found under the key.

    Returns:
        The value as a string, or ``None`` when it is absent or not a scalar.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, bool | int | float):
        return str(value)
    return None


def _read_case_insensitively(headers: object, name: str) -> str | None:
    """Read one header from a transport's header mapping, whatever shape it has.

    Starlette's ``Headers`` is already case-insensitive, so the direct lookup is the whole
    story on every transport mcp ships. The fallback scan is for a host whose transport hands
    over a plain ``dict``, where a case-sensitive miss would silently read as "unauthenticated"
    and fail a caller closed for a reason they could never diagnose.

    Args:
        headers: The transport request's header mapping.
        name: The header name.

    Returns:
        The value, or ``None``.
    """
    getter = getattr(headers, "get", None)
    if callable(getter):
        direct = _as_header_value(getter(name))
        if direct is not None:
            return direct
    items = getattr(headers, "items", None)
    if not callable(items):
        return None
    wanted = name.casefold()
    for key, value in items():
        if isinstance(key, str) and key.casefold() == wanted:
            return _as_header_value(value)
    return None


def _effective_provider(provider: FastMCPProvider | None) -> FastMCPProvider:
    """Resolve the provider a middleware should establish with.

    The one place the defaulting rule lives, so the middleware and :func:`protect_server`
    cannot drift apart. Resolution is deferred to request time on purpose, exactly as on the
    ASGI side: ``install(context_provider=...)`` and the server wiring may then happen in
    either order, which is the difference between a documented ordering constraint and none at
    all.

    A governor wired to some *other* framework's provider is ignored rather than treated as an
    error, since a process may legitimately serve an MCP server beside an HTTP app. The
    fallback is a bare ``_meta``-identifying provider, which fails closed for any caller who
    sends no principal.

    Args:
        provider: An explicitly supplied provider, or ``None``.

    Returns:
        The explicit provider, the installed governor's when it is a :class:`FastMCPProvider`,
        or a freshly built default.
    """
    if provider is not None:
        return provider
    # Imported in the body, as in the other providers: what is read here is *process state*
    # settled by ``install()``, and reaching for it at module import time would be reading it
    # before there is anything to read.
    from sentrykit.engine import current_governor

    governor = current_governor()
    wired = governor.context_provider if governor is not None else None
    if isinstance(wired, FastMCPProvider):
        return wired
    return FastMCPProvider(channel="agent")


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
    discovered: dict[str, Callable[..., object]] = {}
    try:
        # Private attribute, public methods. Guarded as a whole rather than per access,
        # because the failure this tolerates is "mcp reorganized its internals", and that can
        # surface as an ``AttributeError``, a ``TypeError`` or something newer still.
        for tool in server._tool_manager.list_tools():
            name = getattr(tool, "name", None)
            fn = getattr(tool, "fn", None)
            if isinstance(name, str) and callable(fn):
                discovered[name] = fn
    except Exception:
        _LOGGER.warning(
            "Could not read the registered tools from the MCP server; the manifest will not "
            "be filtered. Enforcement on dispatch is unaffected. Pass tools= to filter "
            "without depending on the server's internals",
            exc_info=True,
        )
        return {}
    return discovered


class _ToolRefusal(MCPError):
    """Carries a :class:`~sentrykit.errors.SentrykitError` out of a tool body.

    mcp discards the type of anything a tool raises: ``Tool.run`` wraps it in a ``ToolError``
    and ``MCPServer._handle_call_tool`` turns that into a ``CallToolResult`` whose structured
    content is ``None``, which is precisely the ``_authz`` envelope going missing. Both of them
    make one exception, and it is the same one -- an :class:`mcp.shared.exceptions.MCPError` is
    re-raised untouched, on the grounds that it already describes a protocol-level outcome.

    So a refusal travels as one. This class is private because it is a *transport detail*: it
    exists between :func:`governed_tool`'s translator and
    :meth:`SentrykitToolMiddleware.dispatch`, both of which are in this module, and it is
    unwrapped before anything else can see it.

    Args:
        refusal: The refusal to carry.
    """

    # ``refusal`` rather than ``error``: the base already defines ``error: ErrorData`` and
    # serves ``code``/``message``/``data`` from it, so narrowing that attribute to a different
    # type would be a Liskov violation needing a ``type: ignore`` -- one that is *required*
    # where mcp is installed and *unused* where it is not, so no single spelling satisfies both
    # environments. A separate name shadows nothing, needs no suppression, and leaves the
    # base's own contract intact.
    refusal: SentrykitError

    def __init__(self, refusal: SentrykitError) -> None:
        # Not ``MCPError.__init__``: it would build an ``ErrorData`` this class has no use for.
        # ``code`` is in the implementation-defined server range; the detail travels in the
        # rendered result, not in an error frame.
        super().__init__(code=_REFUSAL_CODE, message=reason_for(refusal))
        self.refusal = refusal

    def __str__(self) -> str:
        """The reason, so an operator logging this exception sees the refusal and not a repr."""
        return reason_for(self.refusal)


def _translating(shim: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a tool shim so a sentrykit refusal escapes mcp's exception laundering.

    The whole body of this wrapper is one ``except`` clause, and it is the difference between a
    model being told ``"Error executing tool search_orders: ..."`` and being handed a structured
    ``_authz`` envelope it can act on. See :class:`_ToolRefusal`.

    The wrapper keeps the shim's ``__signature__`` -- so mcp still advertises the omittable
    parameters :func:`~sentrykit.integrations.tools.proposable` synthesized -- and points
    ``__wrapped__`` at it, so :func:`~sentrykit.integrations.tools.governed_meta` still walks
    through to the ``@protect`` metadata.

    Args:
        shim: The proposable shim around a protected callable. Sync or async; the wrapper
            matches whichever it was given.

    Returns:
        The translating wrapper, ready to register with ``server.tool()``.
    """
    translator: Callable[..., Any]
    if inspect.iscoroutinefunction(shim):

        async def async_translator(**proposed: object) -> object:
            """Await the shim, converting a refusal into one mcp will let out of the body."""
            try:
                return await shim(**proposed)
            except SentrykitError as exc:
                raise _ToolRefusal(exc) from exc

        translator = async_translator
    else:

        def sync_translator(**proposed: object) -> object:
            """Call the shim, converting a refusal into one mcp will let out of the body."""
            try:
                return shim(**proposed)
            except SentrykitError as exc:
                raise _ToolRefusal(exc) from exc

        translator = sync_translator

    functools.update_wrapper(translator, shim)
    # Set explicitly after ``update_wrapper`` for the same reason ``proposable`` does it: the
    # ``__signature__`` is what stops ``inspect.signature`` unwrapping back to the protected
    # callable's required parameters, and it has to survive the copy.
    translator.__signature__ = inspect.signature(shim)  # type: ignore[attr-defined]
    return translator


def governed_tool(
    server: MCPServer,
    *,
    action: str | None = None,
    resource: str | None = None,
    name: str | None = None,
    description: str | None = None,
    optional: Sequence[str] | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Register a protected callable on ``server`` as a governed tool.

    The MCP spelling of :func:`sentrykit.integrations.pydantic_ai.governed_tool`, deliberately
    the same name and the same shape, because the two boundaries should read identically to
    somebody who has only ever wired the other one:

    ```python
    @governed_tool(server, action='Action::"orders.search"', resource='Tool::"orders"')
    def search_orders(region: str, limit: int) -> dict[str, object]: ...
    ```

    It does the three things a governed MCP tool needs, so a host does not have to remember
    them separately: applies ``@protect`` when the callable does not already carry it, makes the
    policy-suppliable arguments omittable with
    :func:`~sentrykit.integrations.tools.proposable`, and registers the result behind the
    translator that lets a refusal out of the tool body. The module docstring says why none of
    those three is optional.

    The **decorated function is returned unchanged** -- protected, and still directly callable
    by ordinary application code under an established context. Registering a tool should not
    take a function away from the rest of the program.

    Args:
        server: The server to register on.
        action: The Cedar action, as for :func:`~sentrykit.decorator.protect`. Ignored when the
            callable is already protected, since re-protecting it would stack two gates and
            silently discard whichever pair the author wrote first.
        resource: The Cedar resource, as for :func:`~sentrykit.decorator.protect`. Ignored when
            the callable is already protected.
        name: Tool name advertised to the model. Defaults to the function's name.
        description: Tool description. Defaults to the function's docstring.
        optional: Which parameters the model may omit, as for
            :func:`~sentrykit.integrations.tools.proposable`. Defaults to every parameter with
            no Python default -- precisely the set whose value could only have come from policy.

    Returns:
        The decorator, which returns the protected callable.

    Raises:
        ConfigurationError: If ``action`` or ``resource`` cannot be parsed, or the callable's
            signature cannot be introspected.
    """

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        """Protect, make omittable, translate, register -- and hand the callable straight back."""
        target = (
            fn if protected_meta(fn) is not None else protect(action=action, resource=resource)(fn)
        )
        # The keyword form applied to an already-built callable, rather than the callable passed
        # positionally alongside keywords: the latter works at runtime but is not one of
        # ``tool``'s declared overloads, and a public integration should type-check as its host
        # declares.
        register = server.tool(name=name, description=description)
        register(_translating(proposable(target, optional=optional)))
        return target

    return decorate


class SentrykitToolMiddleware:
    """Server middleware that governs tool dispatch and filters the tool manifest.

    Implements :class:`mcp.server.context.ServerMiddleware`. Registered outermost-first on
    ``MCPServer.middleware``, it wraps *every* inbound message; everything that is neither
    ``tools/call`` nor ``tools/list`` passes straight through untouched.

    For a ``tools/call`` the lifecycle is the web providers' exactly: establish on the way in,
    release in a ``finally``. The release is not tidiness — a dispatch that kept the previous
    caller's principal would authorize the next model call as somebody else, which is the
    worst failure this library can have.

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
        self._server = server
        # Held as given, not resolved: see :func:`_effective_provider` for why the default is
        # settled at request time rather than at construction.
        self._provider = provider
        self._tools = tools
        self._filter_manifest = filter_manifest

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
        if ctx.method == CALL_TOOL_METHOD:
            return await self.dispatch(ctx, call_next)
        if self._filter_manifest and ctx.method == LIST_TOOLS_METHOD:
            return await self.manifest(ctx, call_next)
        return await call_next(ctx)

    def _tool_source(self) -> Mapping[str, Callable[..., object]]:
        """Resolve tool name → callable for this dispatch.

        Read per message rather than cached at construction, so a server that registers a tool
        after wiring is governed by the same rules as one that registered it before.

        Returns:
            The explicit ``tools`` mapping when one was given, the server's registered tools
            otherwise, and an empty mapping when there is neither.
        """
        if self._tools is not None:
            return self._tools
        return registered_tools(self._server) if self._server is not None else {}

    async def dispatch(
        self, ctx: ServerRequestContext[Any, Any], call_next: CallNext
    ) -> HandlerResult:
        """Establish context for one ``tools/call``, run it, and release.

        A :class:`~sentrykit.errors.SentrykitError` raised by a protected tool is caught and
        rendered as a failed tool result rather than allowed to propagate, because a
        propagating error loses the ``_authz`` envelope (see the module docstring). Anything
        else the tool raises is the tool's business and passes through untouched.

        A tool registered through :func:`governed_tool` delivers its refusal wrapped in a
        :class:`_ToolRefusal`, since that is the only shape mcp lets out of a tool body. A bare
        :class:`~sentrykit.errors.SentrykitError` is caught too — that is what a failure in the
        middleware's own establishment path raises, and it deserves the same rendering.

        The decision itself is made exactly once, inside the decorator, so one dispatch writes
        one audit record. Nothing here re-decides.

        Args:
            ctx: The request context.
            call_next: The rest of the middleware chain.

        Returns:
            The tool's result, or the refusal.
        """
        provider = _effective_provider(self._provider)
        established = provider.establish(ctx)
        try:
            return _report_narrowing(provider, await call_next(ctx))
        except (_ToolRefusal, SentrykitError) as raised:
            refusal = raised.refusal if isinstance(raised, _ToolRefusal) else raised
            _LOGGER.info(
                "Refused a tool call",
                extra={
                    "method": ctx.method,
                    "tool": ctx.params.get("name") if isinstance(ctx.params, Mapping) else None,
                    "reason": type(refusal).__name__,
                },
            )
            return provider.render_error(refusal)
        finally:
            provider.release(established)

    async def manifest(
        self, ctx: ServerRequestContext[Any, Any], call_next: CallNext
    ) -> HandlerResult:
        """Filter a ``tools/list`` result down to what this caller may invoke.

        The result arrives already serialized and carrying its own ``resultType``, so the
        ``tools`` array is rewritten in place and the server's ``_meta`` is left exactly as it
        built it. The **freshness hints are not**: see :func:`_keep_private`.

        An **unauthenticated** caller is shown nothing: with no principal there is no
        entitlement to reason about, and every one of those tools would refuse on dispatch.
        That is the same fail-closed rule as everywhere else, applied to the manifest.

        Args:
            ctx: The request context.
            call_next: The rest of the middleware chain.

        Returns:
            The result, with ``tools`` narrowed.
        """
        result = await call_next(ctx)
        advertised = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(result, dict) or not isinstance(advertised, list):
            # Not the serialized shape this filter knows how to rewrite. Passing it through is
            # the only safe move: enforcement on dispatch is untouched either way.
            return result

        provider = _effective_provider(self._provider)
        # Resolved without establishing: a manifest is a question, not a call, and clearing
        # the ambient context on an unauthenticated ``tools/list`` would be a side effect this
        # message has no business having. The environment is passed explicitly instead, so a
        # policy conditioning on ``context.channel == "agent"`` applies to the probe too.
        narrowed = provider.narrow(ctx)
        principal = provider.resolve_principal(narrowed)
        _keep_private(result)
        if principal is None:
            result["tools"] = []
            return result

        source = self._tool_source()
        permitted = set(
            permitted_tools(
                source, principal=principal, environment=provider.environment_for(narrowed)
            )
        )
        result["tools"] = [
            entry for entry in advertised if _advertise(entry, source=source, permitted=permitted)
        ]
        return result


NARROWED_META_KEY: str = "sentrykit/narrowed"
"""``_meta`` key announcing that a tool call ran with a value the model did not propose."""

NARROWED_ARGUMENTS_META_KEY: str = "sentrykit/narrowedArguments"
"""``_meta`` key naming the narrowed arguments, in first-seen order."""


def _report_narrowing(provider: FastMCPProvider, result: HandlerResult) -> HandlerResult:
    """Carry narrowing out of a ``tools/call`` whose result could not carry it in band.

    A tool returning a mapping gets the whole ``_authz`` envelope inside its own payload, and
    the model reads it there — that path is measured and works. A tool returning a list, a
    string or a model does not: mcp wraps the value as ``structuredContent.result``, there is
    no mapping for :func:`~sentrykit.envelope.attach_envelope` to write into, and the
    narrowing becomes invisible. This is the other half of that story.

    Two destinations, because they answer to different readers:

    * ``_meta`` takes the machine-readable facts. It is the spec's open map for exactly this,
      and the keys are prefixed so they cannot collide with the server's own.
    * one appended text block takes the guidance sentence, because ``_meta`` is protocol
      metadata that a client is under no obligation to show anyone, and the reader who needs
      this is the model. Appended rather than substituted: the tool's own content is
      untouched, so the data still reaches the model exactly as the tool produced it.

    Nothing is added when the envelope already went into the result in band -- a fact the
    boundary's recorder carries rather than a shape this function guesses at, because mcp
    populates ``structuredContent`` only when it has an output schema to validate against and
    the envelope may therefore be in the content text instead.

    Args:
        provider: The provider whose recorder says what was narrowed.
        result: Whatever the handler returned.

    Returns:
        The result. Annotated when there was narrowing to report, and the same object
        untouched otherwise — including for any result shape this does not recognize, since
        a report must never be able to damage the answer it describes.
    """
    narrowed, arguments = provider.narrowing()
    if not narrowed or not isinstance(result, dict):
        return result
    recorder = current_recorder()
    if recorder is not None and recorder.last_was_in_band:
        # The tool returned a mapping and the envelope is already inside it, where the model
        # reads it. Annotating again would say the same thing twice in two places.
        return result

    meta = dict(result.get("_meta") or {})
    meta[NARROWED_META_KEY] = True
    meta[NARROWED_ARGUMENTS_META_KEY] = list(arguments)
    annotated: dict[str, Any] = {**result, "_meta": meta}

    envelope = last_envelope()
    guidance = envelope.guidance if envelope is not None else None
    if guidance is None and arguments:
        # The decision was made in a context whose ``last_envelope`` did not reach here, so
        # the sentence is rebuilt from the names the recorder did carry. The unsupplied-case
        # wording is unavailable this way, so it is not claimed.
        guidance = narrowing_guidance(arguments)
    if guidance is not None:
        content = list(annotated.get("content") or [])
        content.append({"type": "text", "text": guidance})
        annotated["content"] = content
    return annotated


def _keep_private(result: dict[str, Any]) -> None:
    """Downgrade a filtered ``tools/list`` result's cache hints to private, uncacheable.

    mcp attaches ``cacheScope`` and ``ttlMs`` to every cacheable result, and they are a claim
    about *the array the server built* — the full manifest, identical for everybody. Once this
    middleware narrows that array per principal the claim is about a different object, and a
    host that set ``cacheScope="public"`` to cut chatter would have one caller's entitlements
    served to the next from a shared cache. Dispatch still refuses the call, so what leaks is
    *which tools somebody else holds* rather than access to them — but the stated invariant is
    "a tool is hidden iff invoking it would be refused", and a cache that answers for another
    principal makes that sentence false.

    A result whose content depends on the caller is private by construction, so the hints are
    overwritten rather than respected. This is the one part of the envelope the filter owns,
    precisely because it is the one part that describes what the filter changed.
    """
    if "cacheScope" in result:
        result["cacheScope"] = "private"
    if "ttlMs" in result:
        result["ttlMs"] = 0


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
    # Resolved eagerly, unlike inside the middleware, because the return value is the point of
    # the function: a caller asking "what got wired?" must not be answered "whatever is
    # installed by the time the first message arrives".
    resolved = _effective_provider(provider)
    if not any(isinstance(existing, SentrykitToolMiddleware) for existing in server.middleware):
        server.middleware.append(
            SentrykitToolMiddleware(
                server, provider=resolved, tools=tools, filter_manifest=filter_manifest
            )
        )
    return resolved


def _advertise(
    entry: object,
    *,
    source: Mapping[str, Callable[..., object]],
    permitted: frozenset[str] | set[str],
) -> bool:
    """Whether one advertised ``tools/list`` entry survives the filter.

    A name the tool source has never heard of stays visible. That is
    :mod:`sentrykit.integrations.tools`'s rule applied to the manifest: sentrykit does not
    hide a tool it was never given anything to decide about, and quietly dropping one would
    make an unrelated registration look like an authorization failure.

    Args:
        entry: One element of the result's ``tools`` array.
        source: The tool name → callable mapping the decisions were made over.
        permitted: The names this principal may be shown.

    Returns:
        Whether to keep it.
    """
    if not isinstance(entry, Mapping):
        return True
    name = entry.get("name")
    if not isinstance(name, str) or name not in source:
        return True
    return name in permitted
