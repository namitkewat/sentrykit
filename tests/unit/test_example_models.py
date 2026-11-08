"""The examples' model chooser prefers the strongest tier it can reach, and reaches nothing else.

Two properties are worth more than the rest of this file and are the reason it is a unit test
rather than something run by hand. The first is that **offline is the default**: importing the
chooser contacts nothing, resolving a tier contacts nothing but a socket on this machine, and
either live tier can be switched off while its credentials stay exactly where they are. The
second is that **the key stays in the header**: an example prints what it chose, so a choice
that carried a credential into a repr would publish it to a terminal.

Every test here has to hold on a laptop with a key in `.env` and a daemon running, which is the
machine these examples were written on. Neutralising both is the autouse fixture's whole job.
"""

from __future__ import annotations

import importlib.util
import io
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from examples import models, ollama

pytestmark = pytest.mark.unit

KEY = "sk-or-v1-0000000000000000-not-a-real-key"
"""Shaped like the real thing, so a test that hunts for it in a string would find it."""

LOCAL_MODEL = "qwen2.5:3b"
"""What the local daemon is made to report. Any tool-capable name would do."""

DAEMON_URL = "http://daemon.invalid:11434"
"""Where that daemon pretends to be. Reserved, so a missed patch fails rather than connects."""

TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "search_orders",
        "description": "Search the orders desk.",
        "parameters": {"type": "object", "properties": {"region": {"type": "string"}}},
    },
}
"""One tool declaration, in the shape both live tiers read."""

_REAL_PROBE = ollama.tool_capable_models
"""The real local probe, captured before any fixture replaces it."""


def _refuse(*args: object, **kwargs: object) -> object:
    """Fail the test rather than let a socket be opened."""
    raise AssertionError("this must not reach the network")


def _http_error(code: int) -> urllib.error.HTTPError:
    """An HTTP failure in the shape `urllib` raises it."""
    url = f"{models.DEFAULT_OPENROUTER_URL}/chat/completions"
    return urllib.error.HTTPError(url, code, "declined", {}, None)  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def no_live_model(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Pin both live tiers off, whatever the machine running this happens to have.

    The root fixture already empties `SENTRYKIT_OLLAMA_URL`, which turns the local search off
    before a socket is opened. The frontier tier needs three more things said, because none of
    them is named `SENTRYKIT_*` and so none of them is swept by that fixture: the key in the
    environment, the same key in the untracked `.env` the chooser reads when the environment is
    silent, and a CA bundle under the conventional name. A test that read any of the three would
    pass or fail according to whose laptop ran it.

    The local probe is replaced as well rather than merely switched off, so that a test wanting
    a daemon can conjure one without a socket and a test wanting none gets none for a reason
    this file states out loud.

    The frontier URL is pinned to its *default* rather than left alone, which looks like the
    opposite of pinning the tier off and is not. The root fixture empties it, because for the
    suite at large the safe reading of that variable is "off" and the whole point there is that
    no test reaches a paid API. This module is the one that has to exercise the tier being *on*,
    and it does that by the key, which the line above holds. Saying the URL here as well means
    these tests describe their own environment completely instead of inheriting half of it, so
    they keep meaning the same thing whichever way the root fixture later changes.
    """
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, "")
    monkeypatch.setenv(models.OPENROUTER_URL_ENV_VAR, models.DEFAULT_OPENROUTER_URL)
    monkeypatch.setattr(models, "_DOTENV_PATH", tmp_path / "absent.env")
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.setattr(ollama, "tool_capable_models", lambda: ())


def _with_daemon(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the local tier report one tool-capable model, without opening a socket."""
    monkeypatch.setenv(models.OLLAMA_URL_ENV_VAR, DAEMON_URL)
    monkeypatch.setattr(ollama, "tool_capable_models", lambda: (LOCAL_MODEL,))


class _Recorder:
    """A stand-in for `urlopen` that keeps the one request it was given and answers to script.

    Recording the request rather than asserting inside the fake keeps every assertion in the
    test that cares about it — including the ones about where the key did *not* appear, which
    are the point of several tests below.
    """

    def __init__(
        self,
        *,
        answer: object = None,
        raw: bytes | None = None,
        error: Exception | None = None,
    ) -> None:
        """Answer with `raw` bytes, or with `answer` as JSON, or raise `error`."""
        self._answer = answer
        self._raw = raw
        self._error = error
        self.request: urllib.request.Request | None = None
        self.timeout: float | None = None
        self.context: object = None

    def __call__(
        self,
        request: urllib.request.Request,
        *,
        timeout: float | None = None,
        context: object = None,
    ) -> io.BytesIO:
        """Stand in for one call, as `urllib.request.urlopen` is actually invoked."""
        self.request = request
        self.timeout = timeout
        self.context = context
        if self._error is not None:
            raise self._error
        if self._raw is not None:
            return io.BytesIO(self._raw)
        return io.BytesIO(json.dumps(self._answer).encode())

    @property
    def sent(self) -> dict[str, Any]:
        """The body that was posted, decoded."""
        assert self.request is not None
        assert isinstance(self.request.data, bytes)
        body = json.loads(self.request.data)
        assert isinstance(body, dict)
        return body


def _answering(monkeypatch: pytest.MonkeyPatch, **kwargs: Any) -> _Recorder:
    """Install a recorder in place of the one HTTP call the frontier tier makes."""
    recorder = _Recorder(**kwargs)
    monkeypatch.setattr(urllib.request, "urlopen", recorder)
    return recorder


def _load_in_isolation(module: ModuleType) -> ModuleType:
    """Execute a module's body again into a fresh object nothing else can see.

    Replacing the original through `sys.modules` would leave the package attribute pointing at a
    second object while every module that already imported the first keeps using it, which is a
    difference other suites would have to care about. This one is published under a name nobody
    imports and withdrawn again, because a dataclass body resolves its own annotations by
    looking its module up while it runs. Nobody but the caller ends up holding it.
    """
    assert module.__file__ is not None
    name = f"{module.__name__}_reloaded"
    spec = importlib.util.spec_from_file_location(name, module.__file__)
    assert spec is not None
    assert spec.loader is not None
    fresh = importlib.util.module_from_spec(spec)
    sys.modules[name] = fresh
    try:
        spec.loader.exec_module(fresh)
    finally:
        del sys.modules[name]
    return fresh


# --- which tier answers --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key_is_set", "daemon_is_up", "tier", "model"),
    [
        (True, True, models.Tier.OPENROUTER, models.DEFAULT_OPENROUTER_MODEL),
        (True, False, models.Tier.OPENROUTER, models.DEFAULT_OPENROUTER_MODEL),
        (False, True, models.Tier.OLLAMA, LOCAL_MODEL),
        (False, False, models.Tier.NONE, None),
    ],
)
def test_the_strongest_reachable_tier_wins(
    monkeypatch: pytest.MonkeyPatch,
    key_is_set: bool,
    daemon_is_up: bool,
    tier: models.Tier,
    model: str | None,
) -> None:
    """A key outranks a daemon, a daemon outranks nothing, and a daemon never shadows a key."""
    if key_is_set:
        monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    if daemon_is_up:
        _with_daemon(monkeypatch)

    choice = models.choose()

    assert choice.tier is tier
    assert choice.model == model


def test_resolving_the_frontier_tier_asks_openrouter_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A key that is set is taken at its word, so choosing opens no connection at all.

    The alternative — a round trip to find out whether the credential still works — would cost
    every run of every example a wait for an answer it would have to make the same decision
    about anyway.
    """
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    monkeypatch.setattr(urllib.request, "urlopen", _refuse)
    monkeypatch.setattr(socket, "socket", _refuse)

    assert models.choose().tier is models.Tier.OPENROUTER


def test_a_live_choice_carries_an_openai_shaped_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both live tiers hand back a URL an OpenAI-shaped client can be pointed at as it is."""
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    assert models.choose().base_url == models.DEFAULT_OPENROUTER_URL

    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, "")
    _with_daemon(monkeypatch)
    assert models.choose().base_url == f"{DAEMON_URL}/v1"


def test_a_trailing_slash_on_the_configured_url_is_not_doubled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The chooser owns the join, so a URL written either way resolves to the same endpoint."""
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    monkeypatch.setenv(models.OPENROUTER_URL_ENV_VAR, "https://proxy.example/api/v1/")

    assert models.choose().base_url == "https://proxy.example/api/v1"


def test_a_pinned_frontier_model_is_the_one_asked_for(monkeypatch: pytest.MonkeyPatch) -> None:
    """The model variable steers the tier it belongs to."""
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    monkeypatch.setenv(models.OPENROUTER_MODEL_ENV_VAR, "openai/gpt-oss-120b")

    assert models.choose().model == "openai/gpt-oss-120b"


def test_a_blank_pin_is_not_a_model(monkeypatch: pytest.MonkeyPatch) -> None:
    """A variable that was exported empty means "unset", not "ask for the empty model"."""
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    monkeypatch.setenv(models.OPENROUTER_MODEL_ENV_VAR, "   ")

    assert models.choose().model == models.DEFAULT_OPENROUTER_MODEL


# --- the two off switches ------------------------------------------------------------------


def test_the_frontier_switch_falls_through_with_the_key_still_in_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Emptying the frontier URL skips that tier without anyone having to unset a credential.

    Which is what a test suite on a developer's machine needs: the key stays where it is and
    the run is reproducible anyway.
    """
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    monkeypatch.setenv(models.OPENROUTER_URL_ENV_VAR, "")
    _with_daemon(monkeypatch)

    choice = models.choose()

    assert choice.tier is models.Tier.OLLAMA
    assert choice.model == LOCAL_MODEL


def test_both_switches_together_pin_the_deterministic_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With a key set and a daemon up, emptying both URLs still resolves to no model."""
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    monkeypatch.setenv(models.OPENROUTER_URL_ENV_VAR, "")
    _with_daemon(monkeypatch)
    monkeypatch.setenv(models.OLLAMA_URL_ENV_VAR, "")
    monkeypatch.setattr(ollama, "tool_capable_models", _REAL_PROBE)

    choice = models.choose()

    assert choice.tier is models.Tier.NONE
    assert choice.model is None


def test_the_local_switch_returns_before_any_socket_is_opened(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real probe, with the URL emptied, resolves to nothing without reaching for a port."""
    monkeypatch.setattr(ollama, "tool_capable_models", _REAL_PROBE)
    monkeypatch.setenv(models.OLLAMA_URL_ENV_VAR, "")
    monkeypatch.setattr(socket, "socket", _refuse)
    monkeypatch.setattr(socket, "create_connection", _refuse)

    assert models.choose().tier is models.Tier.NONE


# --- where the key comes from --------------------------------------------------------------


@pytest.mark.parametrize("value", ["", "   ", None])
def test_a_key_that_says_nothing_is_no_key(
    monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    """Unset, empty and whitespace all mean the frontier tier is not opted into."""
    if value is None:
        monkeypatch.delenv(models.OPENROUTER_KEY_ENV_VAR, raising=False)
    else:
        monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, value)
    _with_daemon(monkeypatch)

    assert models.choose().tier is models.Tier.OLLAMA


@pytest.mark.parametrize(
    "line",
    [
        "OPENROUTER_API_KEY={key}",
        "export OPENROUTER_API_KEY={key}",
        'OPENROUTER_API_KEY="{key}"',
        "OPENROUTER_API_KEY='{key}'",
    ],
)
def test_a_key_in_the_untracked_dotenv_opts_the_frontier_tier_in(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, line: str
) -> None:
    """The key is expected in a gitignored file, so the chooser reads one rather than a profile."""
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        f"# a comment\n\n{line.format(key=KEY)}\nSOMETHING_ELSE=ignored\n", encoding="utf-8"
    )
    monkeypatch.setattr(models, "_DOTENV_PATH", dotenv)
    monkeypatch.delenv(models.OPENROUTER_KEY_ENV_VAR, raising=False)

    choice = models.choose()

    assert choice.tier is models.Tier.OPENROUTER
    assert choice.api_key == KEY


def test_an_empty_environment_value_beats_a_key_in_the_dotenv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The environment is the louder of the two sources, and "set to nothing" is something said.

    Without that, a suite could not pin the deterministic path on a machine whose `.env` holds
    a working key — it would have to edit the file.
    """
    dotenv = tmp_path / ".env"
    dotenv.write_text(f"OPENROUTER_API_KEY={KEY}\n", encoding="utf-8")
    monkeypatch.setattr(models, "_DOTENV_PATH", dotenv)
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, "")
    _with_daemon(monkeypatch)

    assert models.choose().tier is models.Tier.OLLAMA


def test_a_dotenv_that_is_not_there_is_not_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Most machines have no such file, and the deterministic path is what they should get."""
    monkeypatch.delenv(models.OPENROUTER_KEY_ENV_VAR, raising=False)

    assert models.choose().tier is models.Tier.NONE


# --- what a caller is told when the answer is nothing --------------------------------------


def test_the_reason_accounts_for_both_live_tiers(monkeypatch: pytest.MonkeyPatch) -> None:
    """A reader who turned one tier off still wants to know what happened to the other."""
    monkeypatch.delenv(models.OPENROUTER_KEY_ENV_VAR, raising=False)

    reason = models.choose().reason

    assert models.OPENROUTER_KEY_ENV_VAR in reason
    assert models.OLLAMA_URL_ENV_VAR in reason
    assert "\n" not in reason
    # One clause the caller finishes, as `examples.ollama` writes its half: the sentence it
    # lands in supplies the full stop.
    assert not reason.endswith(".")


def test_the_reason_says_so_when_the_frontier_tier_was_switched_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With a key present, "no key is set" would be a lie, so the switch is named instead."""
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    monkeypatch.setenv(models.OPENROUTER_URL_ENV_VAR, "")

    reason = models.choose().reason

    assert models.OPENROUTER_URL_ENV_VAR in reason
    assert models.OPENROUTER_KEY_ENV_VAR not in reason


def test_the_reason_can_be_asked_for_without_a_choice_in_hand(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An example prints the reason from somewhere other than where it chose a model.

    Both ways of asking read the environment and nothing else, so neither can contradict the
    other about which tier declined and why.
    """
    monkeypatch.delenv(models.OPENROUTER_KEY_ENV_VAR, raising=False)

    assert models.why_no_model() == models.choose().reason


def test_a_live_choice_explains_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """There is nothing to excuse when a model was found, and an example prints the reason."""
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)

    assert models.choose().reason == ""


def test_no_string_the_module_produces_carries_the_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """The credential leaves by one door only, because an example prints what it chose."""
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    _with_daemon(monkeypatch)

    chosen = models.choose()
    monkeypatch.setenv(models.OPENROUTER_URL_ENV_VAR, "")
    refused = models.choose()

    assert chosen.api_key == KEY
    assert "openrouter" in repr(chosen)
    for text in (repr(chosen), str(chosen), chosen.reason, repr(refused), refused.reason):
        assert KEY not in text


# --- sending a turn ------------------------------------------------------------------------


def test_a_frontier_turn_posts_the_conversation_and_the_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One non-streaming completion, against the endpoint the base URL belongs to."""
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    recorder = _answering(monkeypatch, answer={"choices": [{"message": {"content": "hello"}}]})

    message = models.chat(
        models.choose(), [{"role": "user", "content": "find the orders"}], tools=[TOOL]
    )

    assert message == {"content": "hello"}
    assert recorder.request is not None
    assert recorder.request.full_url == f"{models.DEFAULT_OPENROUTER_URL}/chat/completions"
    assert recorder.sent["model"] == models.DEFAULT_OPENROUTER_MODEL
    assert recorder.sent["messages"] == [{"role": "user", "content": "find the orders"}]
    assert recorder.sent["stream"] is False
    assert recorder.sent["tools"] == [TOOL]


def test_a_turn_with_no_tools_declares_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty tool list is not a tool list, and an API that is sent one may object to it."""
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    recorder = _answering(monkeypatch, answer={"choices": [{"message": {"content": ""}}]})

    models.chat(models.choose(), [{"role": "user", "content": "hi"}], tools=[])

    assert "tools" not in recorder.sent


def test_the_key_travels_in_a_header_and_in_nothing_else(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A URL reaches proxy logs and a raised error; a body reaches whatever printed it."""
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    recorder = _answering(monkeypatch, answer={"choices": [{"message": {"content": ""}}]})

    models.chat(models.choose(), [{"role": "user", "content": "hi"}])

    assert recorder.request is not None
    assert recorder.request.get_header("Authorization") == f"Bearer {KEY}"
    assert KEY not in recorder.request.full_url
    assert isinstance(recorder.request.data, bytes)
    assert KEY not in recorder.request.data.decode()


@pytest.mark.parametrize(
    "error",
    [
        urllib.error.URLError("no route to host"),
        _http_error(401),
        _http_error(404),
        ssl.SSLCertVerificationError("unable to get local issuer certificate"),
        TimeoutError("timed out"),
    ],
)
def test_a_turn_that_did_not_happen_is_no_answer_rather_than_a_failure(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    """A refused key, a model id with a typo in it and a broken handshake all arrive alike.

    The caller has one decision to make about all of them — say so and carry on — and a typo in
    an environment variable must not stop an example running.
    """
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    _answering(monkeypatch, error=error)

    assert models.chat(models.choose(), [{"role": "user", "content": "hi"}]) is None


@pytest.mark.parametrize(
    "answer", [{}, {"choices": []}, {"choices": [{}]}, {"choices": "nope"}, [], None]
)
def test_an_answer_outside_the_documented_shape_is_no_answer(
    monkeypatch: pytest.MonkeyPatch, answer: object
) -> None:
    """Nothing downstream has to guard what it was handed, so this is where the shape is checked."""
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    _answering(monkeypatch, answer=answer)

    assert models.chat(models.choose(), [{"role": "user", "content": "hi"}]) is None


def test_a_body_that_is_not_json_is_no_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    """A captive portal or a proxy error page answers with a page, and answers it with a 200."""
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    _answering(monkeypatch, raw=b"<!doctype html><title>Sign in</title>")

    assert models.chat(models.choose(), [{"role": "user", "content": "hi"}]) is None


def test_a_local_turn_goes_through_the_local_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """The local tier owns its own API, so the chooser forwards rather than reimplementing it."""
    _with_daemon(monkeypatch)
    monkeypatch.setattr(urllib.request, "urlopen", _refuse)
    seen: dict[str, Any] = {}

    def fake_chat(
        model: str, messages: list[dict[str, Any]], *, tools: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        seen.update(model=model, messages=messages, tools=tools)
        return {"content": "", "tool_calls": [{"function": {"name": "search_orders"}}]}

    monkeypatch.setattr(ollama, "chat", fake_chat)

    message = models.chat(models.choose(), [{"role": "user", "content": "hi"}], tools=[TOOL])

    assert seen == {
        "model": LOCAL_MODEL,
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [TOOL],
    }
    assert message == {"content": "", "tool_calls": [{"function": {"name": "search_orders"}}]}


def test_no_model_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """A caller that asks anyway gets the same ``None`` it would get from a failed turn."""
    monkeypatch.setattr(urllib.request, "urlopen", _refuse)
    monkeypatch.setattr(ollama, "chat", _refuse)

    choice = models.choose()

    assert choice.tier is models.Tier.NONE
    assert models.chat(choice, [{"role": "user", "content": "hi"}]) is None


# --- TLS on a machine that intercepts it ---------------------------------------------------


@pytest.mark.parametrize("variable", ["SENTRYKIT_CA_BUNDLE", "SSL_CERT_FILE"])
def test_a_configured_ca_bundle_is_what_tls_is_verified_against(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, variable: str
) -> None:
    """A machine whose egress is intercepted signs with a CA no shipped bundle carries."""
    bundle = tmp_path / "corp.pem"
    bundle.write_text("", encoding="utf-8")
    pinned = object()
    seen: dict[str, Any] = {}

    def fake_context(*args: Any, **kwargs: Any) -> object:
        seen.update(kwargs)
        return pinned

    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    monkeypatch.setenv(variable, str(bundle))
    monkeypatch.setattr(ssl, "create_default_context", fake_context)
    recorder = _answering(monkeypatch, answer={"choices": [{"message": {"content": ""}}]})

    models.chat(models.choose(), [{"role": "user", "content": "hi"}])

    assert seen["cafile"] == str(bundle)
    assert recorder.context is pinned


def test_the_sentrykit_bundle_is_the_one_consulted_first(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Pointing this module at a bundle should not have to change what every other library uses."""
    ours = tmp_path / "ours.pem"
    ours.write_text("", encoding="utf-8")
    theirs = tmp_path / "theirs.pem"
    theirs.write_text("", encoding="utf-8")
    seen: dict[str, Any] = {}

    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    monkeypatch.setenv("SENTRYKIT_CA_BUNDLE", str(ours))
    monkeypatch.setenv("SSL_CERT_FILE", str(theirs))
    monkeypatch.setattr(ssl, "create_default_context", lambda *a, **kw: seen.update(kw))
    _answering(monkeypatch, answer={"choices": [{"message": {"content": ""}}]})

    models.chat(models.choose(), [{"role": "user", "content": "hi"}])

    assert seen["cafile"] == str(ours)


def test_a_bundle_that_cannot_be_loaded_leaves_verification_alone(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A stale path in an environment variable should not stop an example running."""
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    monkeypatch.setenv("SENTRYKIT_CA_BUNDLE", str(tmp_path / "gone.pem"))
    recorder = _answering(monkeypatch, answer={"choices": [{"message": {"content": "hello"}}]})

    message = models.chat(models.choose(), [{"role": "user", "content": "hi"}])

    assert message == {"content": "hello"}
    assert recorder.context is None


def test_no_bundle_leaves_verification_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ordinary machine configures nothing and gets the default trust store."""
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    recorder = _answering(monkeypatch, answer={"choices": [{"message": {"content": ""}}]})

    models.chat(models.choose(), [{"role": "user", "content": "hi"}])

    assert recorder.context is None


# --- offline by default --------------------------------------------------------------------


def test_importing_the_chooser_contacts_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Import time is the one moment a caller cannot opt out of, so nothing happens there.

    Both modules are executed again rather than inspected, because a probe at import would be
    invisible to a reading of the public surface and obvious here.
    """
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, KEY)
    _with_daemon(monkeypatch)
    monkeypatch.setattr(socket, "socket", _refuse)
    monkeypatch.setattr(socket, "create_connection", _refuse)
    monkeypatch.setattr(urllib.request, "urlopen", _refuse)

    for module in (ollama, models):
        fresh = _load_in_isolation(module)
        assert fresh.__name__.endswith("_reloaded")

    assert models.choose().tier is models.Tier.OPENROUTER
