"""A minimal FastAPI app wired to sentrykit, exercising the whole decision pipeline.

Run it with `pixi run -e web run-fastapi` and drive it with the `curl` recipes in this
directory's README. Three routes cover the three things the library claims to do:

* `GET /orders` — a **sync** route. Omitting a query parameter demonstrates *default
  injection*; passing a disallowed one demonstrates *argument filtering*. It is `def` rather
  than `async def` on purpose, so the example proves ambient context survives the AnyIO
  worker-thread hop.
* `POST /orders/export` — an **async** route, refused two different ways: by role, and by a
  `forbid` policy that reads the proposed argument.
* `GET /orders/summary` — an **unprotected** route calling a **protected** function. The gate
  is on the callable, not the URL.

Authentication is a stub: the `x-user` header names the principal. That is the seam a real app
replaces with its session, its bearer token, or its gateway's assertion — everything below the
`identify` callback is unchanged by that choice.

No route declares a pydantic `response_model`. One would strip the `_authz` key the engine
attaches to the returned mapping, and the envelope is half of what this example is showing.
"""

from __future__ import annotations

from fastapi import FastAPI
from starlette.requests import Request

from examples.fastapi_app.policy import POLICY_TEXT, build_grants
from examples.fastapi_app.service import export_orders, search_orders, summarize_orders
from sentrykit import configure, install
from sentrykit.integrations.fastapi import FastAPIProvider, protect_app


def _identify(request: Request) -> str | None:
    """The example's authentication stub: the caller names themselves in ``x-user``.

    Returning ``None`` means *unauthenticated*, not *error* — the request proceeds and every
    protected call inside it fails closed with a 403, which is the behaviour worth showing.

    Args:
        request: The incoming request.

    Returns:
        The principal id, or ``None``.
    """
    return request.headers.get("x-user")


def create_app() -> FastAPI:
    """Wire settings, grants, policy, the provider and the routes into one app.

    Returns:
        The application, with sentrykit's middleware and error handlers installed.
    """
    # ``verbose`` so the ``_authz`` envelope actually carries processed values, applied
    # defaults and rejection reasons. A production service would leave this at ``summary``.
    configure(verbosity="verbose")

    store = build_grants()
    provider = FastAPIProvider(identify=_identify, grants=store)
    install(POLICY_TEXT, grant_store=store, context_provider=provider)

    app = FastAPI(title="sentrykit example — orders API")
    protect_app(app, provider=provider)

    @app.get("/orders")
    def list_orders(region: str | None = None, limit: int | None = None) -> dict[str, object]:
        """Search orders, forwarding **only** the parameters the caller actually supplied.

        The omission is the demonstration: an absent parameter is never forwarded as ``None``,
        so policy sees a genuinely unproposed argument and fills it from the principal's
        default.
        """
        proposed: dict[str, object] = {}
        if region is not None:
            proposed["region"] = region
        if limit is not None:
            proposed["limit"] = limit
        return search_orders(**proposed)

    @app.post("/orders/export")
    async def export(request: Request) -> dict[str, object]:
        """Export orders in the format the body proposes.

        The body is read by hand rather than through a pydantic model, so the proposed ``fmt``
        reaches policy exactly as the caller wrote it — untrusted data, validated by the
        engine after the gate rather than before it.
        """
        body = await request.json()
        return export_orders(fmt=body["fmt"])

    @app.get("/orders/summary")
    def summary() -> dict[str, object]:
        """Call a protected function from an unprotected route.

        Nothing on this route mentions authorization; the refusal, when it comes, is raised
        three frames deeper by :func:`~examples.fastapi_app.service.summarize_orders`.
        """
        return summarize_orders()

    return app


app = create_app()
"""The module-level app `uvicorn examples.fastapi_app.main:app` serves."""
