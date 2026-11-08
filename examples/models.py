"""One answer to "what model should I use?", from the best tier within reach.

Both agent examples want a live model, because the whole claim is *the model proposes, the
policy decides* and a scripted stand-in only ever demonstrates the second half. Neither cares
*which* live model: the decision is made from the principal and the proposed arguments and
never from which model proposed them, so every authorization outcome is identical on all three
of the tiers below. What a stronger model buys is a better proposal — it picks the tool, it
drafts the arguments, and when it drafts them badly, sentrykit refusing the call is exactly the
point rather than a failure of the demonstration.

The tiers, in the order this module tries them:

1. **A frontier model over [OpenRouter](https://openrouter.ai).** The strongest proposals, and
   the only tier that costs anything, so it is opt-in: nothing here reaches for it unless
   `OPENROUTER_API_KEY` is set. The place to put it is `.env` at the repository root, which is
   not tracked, and which this module reads when the environment is silent.
2. **A local [Ollama](https://ollama.com) daemon.** No key, no account, nothing to pay for —
   found by :mod:`examples.ollama`, which also owns the probing and the client for it.
3. **A deterministic stand-in.** No network at all. What the test suite runs on, and what
   anyone with neither of the above gets. The stand-in itself stays with the caller, which
   already has one and knows what it wants driven; what this module contributes is the answer
   that there is nothing live, and one sentence saying why.

Offline is the default and stays the default. Importing this module contacts nothing.
:func:`choose` asks the local daemon whether it is there — a socket on this machine, never the
network — and asks OpenRouter nothing at all, because a key that is set is taken at its word.
Only :func:`chat` leaves the machine.

Everything here is standard library, for the reason :mod:`examples.ollama` is: an example meant
to run with nothing installed must not acquire a dependency just to make one HTTP request, and
`urllib` makes this one — a POST with a bearer header, against a configurable trust store —
without reaching for anything.

Configuration is environment variables, all optional:

| variable | default | meaning |
| --- | --- | --- |
| `OPENROUTER_API_KEY` | unset | the key; without it the frontier tier is skipped entirely |
| `SENTRYKIT_OPENROUTER_URL` | `https://openrouter.ai/api/v1` | where to send; empty turns it off |
| `SENTRYKIT_OPENROUTER_MODEL` | `anthropic/claude-haiku-5.5` | which model id to ask for |
| `SENTRYKIT_CA_BUNDLE` | unset | a CA bundle to verify TLS against |
| `SSL_CERT_FILE` | unset | the same, under the conventional name; the variable above wins |
| `SENTRYKIT_OLLAMA_URL` | `http://localhost:11434` | where the daemon is; empty means do not look |
| `SENTRYKIT_OLLAMA_MODEL` | the first tool-capable model it reports | which local model to use |

Each live tier has an off switch, and they are independent on purpose. Setting
`SENTRYKIT_OLLAMA_URL` to an empty value turns the local search off without opening a socket;
setting `SENTRYKIT_OPENROUTER_URL` to an empty value turns the frontier tier off *while the key
stays in the environment*. Both together pin the deterministic path. That is what a test suite
wants — an example's behaviour must not depend on what the machine running it happens to have,
and a test that reached for a live model would be asserting against a different model on every
developer's laptop — and it is also the pair to reach for when you have both and want the
reproducible run anyway.

Nothing that cannot be reached is an error. A key that has expired, a model id with a typo in
it, an outage, and a TLS handshake the machine's own proxy broke are four ways to not have an
answer, and all four arrive as *no answer*: :func:`chat` returns ``None`` and the caller says
so and carries on. A typo in an environment variable should not stop an example running.
"""

from __future__ import annotations

import json
import os
import pathlib
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from examples import ollama

__all__ = [
    "DEFAULT_OPENROUTER_MODEL",
    "DEFAULT_OPENROUTER_URL",
    "OLLAMA_MODEL_ENV_VAR",
    "OLLAMA_URL_ENV_VAR",
    "OPENROUTER_KEY_ENV_VAR",
    "OPENROUTER_MODEL_ENV_VAR",
    "OPENROUTER_URL_ENV_VAR",
    "Choice",
    "Tier",
    "chat",
    "choose",
    "why_no_model",
]

OPENROUTER_KEY_ENV_VAR: Final = "OPENROUTER_API_KEY"
"""Environment variable holding the OpenRouter key. Its presence is what opts the tier in."""

OPENROUTER_URL_ENV_VAR: Final = "SENTRYKIT_OPENROUTER_URL"
"""Environment variable naming OpenRouter's base URL; empty means do not use the tier."""

OPENROUTER_MODEL_ENV_VAR: Final = "SENTRYKIT_OPENROUTER_MODEL"
"""Environment variable pinning which frontier model to ask for."""

DEFAULT_OPENROUTER_URL: Final = "https://openrouter.ai/api/v1"
"""OpenRouter's OpenAI-compatible base URL."""

DEFAULT_OPENROUTER_MODEL: Final = "anthropic/claude-haiku-5.5"
"""The model asked for when none is pinned.

Small enough to answer an example promptly and to cost about nothing, and good enough at tool
use that the proposals it makes are worth watching a policy decide on.
"""

OLLAMA_URL_ENV_VAR: Final = ollama.URL_ENV_VAR
"""Environment variable naming the local daemon's base URL, named here too.

The local tier's two knobs are re-exported so that an example configuring either tier, or
printing the name of a knob a reader could turn, needs one import rather than two.
"""

OLLAMA_MODEL_ENV_VAR: Final = ollama.MODEL_ENV_VAR
"""Environment variable pinning which local model to use, named here too."""

_CA_BUNDLE_ENV_VARS: Final = ("SENTRYKIT_CA_BUNDLE", "SSL_CERT_FILE")
"""Where to look for a CA bundle, in order; the first one that is set decides."""

_DOTENV_PATH: Final = pathlib.Path(__file__).resolve().parents[1] / ".env"
"""The untracked file at the repository root that a key is expected to live in."""

_CHAT_TIMEOUT: Final = 120.0
"""Seconds to wait for a completion. Long enough for a reasoning model on a slow link."""


class Tier(StrEnum):
    """Which kind of model answered, or that none did."""

    OPENROUTER = "openrouter"
    """A frontier model, over OpenRouter's API."""

    OLLAMA = "ollama"
    """A local daemon's model."""

    NONE = "none"
    """Nothing live is within reach, and :attr:`Choice.reason` says why."""


@dataclass(frozen=True)
class Choice:
    """What to run on, and — when the answer is nothing — why it is nothing.

    Attributes:
        tier: Which tier answered. :attr:`Tier.NONE` exactly when :attr:`model` is ``None``,
            so either one answers "is a live model available?".
        model: The model id to ask for, or ``None`` when there is nothing to ask.
        base_url: The OpenAI-compatible base URL the model is behind, with no trailing slash,
            which is what an OpenAI-shaped client wants for either live tier. Empty when there
            is no model.
        api_key: The credential for :attr:`base_url`, or ``None`` on a tier that needs none.
            Kept out of the repr so that printing or logging a choice — which an example does —
            cannot leak it.
        reason: One sentence completing "this runs on a stand-in because ...". Empty unless
            :attr:`tier` is :attr:`Tier.NONE`.
    """

    tier: Tier
    model: str | None = None
    base_url: str = ""
    api_key: str | None = field(default=None, repr=False)
    reason: str = ""


def _dotenv_value(name: str) -> str | None:
    """Read one variable out of the repository-root `.env`, without a parser for it.

    A key belongs in a gitignored file rather than in a shell profile, and an example that read
    only `os.environ` would make every reader export it by hand. What this understands is the
    strict subset every `.env` file agrees on — ``NAME=value``, optionally `export`-ed,
    optionally quoted — because a line more elaborate than that was not written for an example.

    Args:
        name: The variable to look for.

    Returns:
        Its value, or ``None`` when the file is absent, unreadable, or does not set it.
    """
    try:
        text = _DOTENV_PATH.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None

    for line in text.splitlines():
        head, _, tail = line.partition("=")
        # A commented-out line keeps its `#`, so it simply fails to match the name and needs no
        # case of its own here.
        if head.strip().removeprefix("export ").strip() != name:
            continue
        return tail.strip().strip("\"'") or None
    return None


def _api_key() -> str | None:
    """Find the OpenRouter key, or report that there is none.

    The environment wins outright, and *being set at all* is what counts: an empty value means
    "no key" and stops the file being consulted. That is the switch a test suite needs on a
    machine whose `.env` holds a real key, and it is why the two sources are not merged.

    Returns:
        The key, or ``None`` when neither source sets it to anything.
    """
    configured = os.environ.get(OPENROUTER_KEY_ENV_VAR)
    if configured is not None:
        return configured.strip() or None
    return _dotenv_value(OPENROUTER_KEY_ENV_VAR)


def _openrouter_url() -> str:
    """Return OpenRouter's base URL, with no trailing slash.

    Returns:
        The configured URL, or :data:`DEFAULT_OPENROUTER_URL`. Empty when the tier has been
        turned off by setting :data:`OPENROUTER_URL_ENV_VAR` to the empty string.
    """
    return os.environ.get(OPENROUTER_URL_ENV_VAR, DEFAULT_OPENROUTER_URL).strip().rstrip("/")


def why_no_model() -> str:
    """Explain, in one sentence, why the deterministic path was taken.

    This is the sentence :func:`choose` puts in :attr:`Choice.reason`, and it is available on
    its own because an example prints it from somewhere other than where it chose. It reads the
    environment and asks nothing, so the two can never disagree.

    Both halves appear, because "no model" has two independent causes and a reader who turned
    one tier off still wants to know what happened to the other. The local half is the clause
    :mod:`examples.ollama` writes for itself, so neither module can drift into contradicting
    the other about why a daemon went unused.

    Returns:
        A sentence that completes "this runs on a stand-in because ...". Only true on that
        path: a key that is set and a tier that is on make the first half say the tier was
        switched off, because that is the one way left for :func:`choose` to have declined it.
    """
    if _api_key() is None:
        frontier = f"no {OPENROUTER_KEY_ENV_VAR} is set"
    else:
        frontier = (
            f"the frontier tier is turned off ({OPENROUTER_URL_ENV_VAR} is set to an empty value)"
        )
    return f"{frontier}, and locally {ollama.why_no_model()}"


def choose() -> Choice:
    """Answer what to run on, trying the tiers in their order of preference.

    A key that is set is taken at its word: nothing is asked of OpenRouter here, because the
    only question this function can answer is which tier to *try*, and a round trip to find out
    whether a credential still works would cost every run of every example a second for an
    answer it would then have to make the same decision about anyway. A key that has expired
    therefore shows up as a turn that did not happen rather than as a fall back to the daemon
    below it — to reach that one, unset the key or empty :data:`OPENROUTER_URL_ENV_VAR`.

    Returns:
        The frontier tier when a key is set and the tier is not turned off; otherwise the local
        daemon's first tool-capable model; otherwise a :attr:`Tier.NONE` choice carrying the
        reason in :attr:`Choice.reason`.
    """
    url = _openrouter_url()
    key = _api_key()
    if url and key:
        pinned = os.environ.get(OPENROUTER_MODEL_ENV_VAR, "").strip()
        return Choice(
            tier=Tier.OPENROUTER,
            model=pinned or DEFAULT_OPENROUTER_MODEL,
            base_url=url,
            api_key=key,
        )

    local = ollama.choose_model()
    if local is not None:
        return Choice(tier=Tier.OLLAMA, model=local, base_url=f"{ollama.endpoint()}/v1")

    return Choice(tier=Tier.NONE, reason=why_no_model())


def chat(
    choice: Choice,
    messages: list[dict[str, Any]],
    *,
    tools: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Run one non-streaming chat turn on the chosen tier and return the assistant message.

    The minimum an example needs to let a model choose a tool. A caller that drives a model
    through an agent framework does not need this at all — it hands :func:`choose`'s answer to
    that framework's provider instead — but an MCP *server* owns no model client, and this is
    what lets it drive itself end to end without taking on an agent framework to do it.

    Args:
        choice: What :func:`choose` answered.
        messages: The conversation so far, as ``{"role", "content"}`` mappings. Both live tiers
            read the same shape.
        tools: JSON-schema tool declarations the model may propose calls against, in OpenAI's
            ``{"type": "function", "function": {...}}`` form. Both live tiers read that too.

    Returns:
        The assistant message, carrying ``content`` and, when the model proposed one,
        ``tool_calls``. ``None`` when there was no model to ask or the turn did not happen.
        A proposal's ``function.arguments`` is an object on the local tier and a JSON string on
        the frontier one, because that is how each API answers; a caller that reads proposed
        arguments has to accept both rather than trust one.
    """
    if choice.model is None:
        return None
    if choice.tier is Tier.OPENROUTER:
        return _openrouter_chat(choice, messages, tools=tools)
    if choice.tier is Tier.OLLAMA:
        return ollama.chat(choice.model, messages, tools=tools)
    return None


def _openrouter_chat(
    choice: Choice,
    messages: list[dict[str, Any]],
    *,
    tools: list[dict[str, Any]] | None,
) -> dict[str, Any] | None:
    """Post one completion to OpenRouter's OpenAI-compatible endpoint.

    Every way this can fail collapses into one ``None``, the way the local tier's probe does:
    the caller has exactly one decision to make — report the turn and carry on, or not — and
    distinguishing a refused credential from a misspelled model id from a broken handshake
    would only give it more ways to get that decision wrong.

    Args:
        choice: The frontier-tier choice to run on.
        messages: The conversation so far.
        tools: Tool declarations, or ``None`` to offer none.

    Returns:
        The assistant message, or ``None`` if OpenRouter could not be reached, declined, or did
        not answer in the shape its API documents.
    """
    if not choice.api_key or not choice.base_url:
        return None

    payload: dict[str, Any] = {"model": choice.model, "messages": messages, "stream": False}
    if tools:
        payload["tools"] = tools
    # The key travels in a header and in nothing else. Not in the URL, which a proxy log and a
    # raised `HTTPError` both carry, and not in the body, which an example may well print.
    request = urllib.request.Request(
        f"{choice.base_url}/chat/completions",
        data=json.dumps(payload).encode(),
        headers={
            "content-type": "application/json",
            "authorization": f"Bearer {choice.api_key}",
        },
    )

    context = _tls_context()
    try:
        with urllib.request.urlopen(request, timeout=_CHAT_TIMEOUT, context=context) as response:
            answer = json.load(response)
    except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError):
        return None

    choices = answer.get("choices") if isinstance(answer, dict) else None
    first = choices[0] if isinstance(choices, list) and choices else None
    message = first.get("message") if isinstance(first, dict) else None
    return message if isinstance(message, dict) else None


def _tls_context() -> ssl.SSLContext | None:
    """Verify TLS against a configured CA bundle, when the machine needs one.

    A machine whose egress is intercepted presents a certificate signed by its own CA. That CA
    is in the system store and not in the bundle a Python process compiles against, so the
    handshake fails verification and no amount of retrying fixes it. Either variable names a
    bundle that includes it; the sentrykit-specific one is consulted first so that pointing this
    module at a bundle does not have to change how every other library on the machine resolves
    certificates.

    Returns:
        A context pinned to the configured bundle, or ``None`` to leave the default
        verification alone — including when the configured path is missing or is not a bundle,
        because a stale path in an environment variable should not stop an example running.
    """
    for name in _CA_BUNDLE_ENV_VARS:
        bundle = os.environ.get(name, "").strip()
        if not bundle:
            continue
        try:
            return ssl.create_default_context(cafile=bundle)
        except (OSError, ssl.SSLError):
            return None
    return None
