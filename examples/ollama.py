"""Optional local-model support for the two agent examples.

A model is what makes an agent example honest: the whole claim is *the model proposes, the
policy decides*, and a scripted stand-in only ever demonstrates the second half. So both agent
examples will use a real model when one is within reach — an [Ollama](https://ollama.com)
daemon on the machine, which needs no API key and no account — and fall back to a
deterministic stand-in when it is not.

The fallback is not a lesser mode. Every authorization outcome the examples demonstrate is
identical either way, because the decision is made from the principal and the proposed
arguments and never from which model proposed them. What a live model adds is that the
proposal is genuinely the model's: it picks the tool, it drafts the arguments, and sometimes it
drafts them badly. That last case is worth watching rather than hiding — sentrykit refusing a
call the model should not have proposed is exactly the point.

Everything here is standard library. Probing a daemon must not put a dependency in an example
that is meant to run with nothing installed, and the two callers need different clients
anyway: the Pydantic-AI example drives Ollama through that library's own provider, and the MCP
example drives it through :func:`chat` below, because an MCP server has no model of its own.

Configuration is two environment variables, both optional:

| variable | default | meaning |
| --- | --- | --- |
| `SENTRYKIT_OLLAMA_URL` | `http://localhost:11434` | where the daemon is; empty means do not look |
| `SENTRYKIT_OLLAMA_MODEL` | the first tool-capable model it reports | which model to use |

Naming a model that the daemon does not have is treated as *no model*: the examples fall back
rather than failing, because a typo in an environment variable should not stop an example
running.

Setting `SENTRYKIT_OLLAMA_URL` to the empty string turns the search off outright — no socket is
opened and no model is found, so the examples take the deterministic path. That is what a test
suite wants: an example's behaviour must not depend on whether the machine running it happens
to have a daemon, and a test that reached for one would be asserting against a different model
on every developer's laptop. It is also the switch to reach for when you have a daemon and want
the reproducible run anyway.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Final

__all__ = [
    "DEFAULT_URL",
    "MODEL_ENV_VAR",
    "URL_ENV_VAR",
    "chat",
    "choose_model",
    "endpoint",
    "tool_capable_models",
    "why_no_model",
]

URL_ENV_VAR: Final = "SENTRYKIT_OLLAMA_URL"
"""Environment variable naming the daemon's base URL."""

MODEL_ENV_VAR: Final = "SENTRYKIT_OLLAMA_MODEL"
"""Environment variable pinning which model to use."""

DEFAULT_URL: Final = "http://localhost:11434"
"""Where Ollama listens unless it was told otherwise."""

_PROBE_TIMEOUT: Final = 1.5
"""Seconds to wait when asking whether a daemon is there.

Short on purpose. The answer is almost always immediate — the daemon is on this machine or it
is not — and an example that paused for ten seconds before printing anything would read as
broken. A firewall that black-holes the port is the case this bounds.
"""

_CHAT_TIMEOUT: Final = 120.0
"""Seconds to wait for a completion. A small model on a laptop CPU is not fast."""


def endpoint() -> str:
    """Return the daemon's base URL, with no trailing slash.

    Returns:
        The configured URL, or :data:`DEFAULT_URL`. Empty when the search has been turned off
        by setting :data:`URL_ENV_VAR` to the empty string.
    """
    return os.environ.get(URL_ENV_VAR, DEFAULT_URL).strip().rstrip("/")


def _post(path: str, payload: dict[str, Any] | None, *, timeout: float) -> Any | None:
    """Call one Ollama endpoint, returning ``None`` for every reachability failure.

    Collapsing "no daemon", "wrong port", "daemon is starting" and "malformed answer" into one
    ``None`` is deliberate. The caller has exactly one decision to make — use a live model or
    do not — and distinguishing the ways a daemon can be absent would only give it more ways to
    get that decision wrong.

    Args:
        path: The endpoint path, beginning with a slash.
        payload: A JSON body, or ``None`` to issue a ``GET``.
        timeout: How long to wait.

    Returns:
        The decoded JSON answer, or ``None`` if the daemon could not be reached or did not
        answer with JSON.
    """
    base = endpoint()
    if not base:
        # The search is off. Returning before opening a socket is the whole point: this is the
        # path a test suite takes, and it must not depend on what is listening on this machine.
        return None

    # The URL is this module's own, assembled from configuration rather than from anything a
    # caller or a model supplied.
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        f"{base}{path}",
        data=body,
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError):
        return None


def tool_capable_models() -> tuple[str, ...]:
    """Name the installed models that can be given tools.

    Tool support is a property of the model's template, not of Ollama, so a daemon can be
    running and still have nothing that can drive an agent. Asking beforehand turns that into
    a clean fallback instead of a failed run.

    Returns:
        The model names, in the order the daemon lists them. Empty when no daemon answered or
        when none of the installed models advertises tool support.
    """
    tags = _post("/api/tags", None, timeout=_PROBE_TIMEOUT)
    if not isinstance(tags, dict):
        return ()

    capable: list[str] = []
    for entry in tags.get("models", []):
        name = entry.get("name") if isinstance(entry, dict) else None
        if not isinstance(name, str):
            continue
        shown = _post("/api/show", {"model": name}, timeout=_PROBE_TIMEOUT)
        capabilities = shown.get("capabilities") if isinstance(shown, dict) else None
        if isinstance(capabilities, list) and "tools" in capabilities:
            capable.append(name)
    return tuple(capable)


def choose_model() -> str | None:
    """Pick the model to run on, or report that there is none.

    Returns:
        The model named in :data:`MODEL_ENV_VAR` when the daemon actually has it, otherwise
        the first tool-capable model it reports, otherwise ``None``.
    """
    capable = tool_capable_models()
    if not capable:
        return None

    pinned = os.environ.get(MODEL_ENV_VAR)
    if pinned:
        # A pinned name that is not installed falls through to the automatic choice rather
        # than failing: the point of the variable is to steer the example, not to gate it.
        return pinned if pinned in capable else capable[0]
    return capable[0]


def why_no_model() -> str:
    """Explain, in one clause, why the deterministic path was taken.

    The two reasons want different sentences and an example that ran them together would
    print "no model at " to anyone who turned the search off. Both examples print this, so
    both say the same thing.

    Returns:
        A clause that completes "this section runs on a stand-in because ...".
    """
    base = endpoint()
    if not base:
        return f"the search for one is turned off ({URL_ENV_VAR} is set to an empty value)"
    return f"no tool-capable model answered at {base}"


def chat(
    model: str,
    messages: list[dict[str, Any]],
    *,
    tools: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Run one non-streaming chat turn and return the assistant message.

    The minimum an example needs to let a model choose a tool, written against Ollama's own
    ``/api/chat`` so that the MCP example — which is a *server*, and owns no model client —
    can drive itself end to end without taking on an agent framework to do it.

    Args:
        model: The model name.
        messages: The conversation so far, in Ollama's ``{"role", "content"}`` form.
        tools: JSON-schema tool declarations the model may propose calls against.

    Returns:
        The assistant message, which carries ``content`` and, when the model proposed one,
        ``tool_calls``. ``None`` when the daemon could not be reached.
    """
    payload: dict[str, Any] = {"model": model, "messages": messages, "stream": False}
    if tools:
        payload["tools"] = tools
    answer = _post("/api/chat", payload, timeout=_CHAT_TIMEOUT)
    if not isinstance(answer, dict):
        return None
    message = answer.get("message")
    return message if isinstance(message, dict) else None
