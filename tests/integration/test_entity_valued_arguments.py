"""What a caller can choose when a protected parameter is annotated as an entity reference.

Every web and agent integration validates the caller's JSON against the protected callable's
annotations **before** the decorator runs — the wrapper is signature-preserving precisely so
that framework introspection sees the original function. A parameter typed ``EntityRef`` is
therefore a caller-chosen entity, and the caller chooses its **type** as well as its id.

That is a genuine sharp edge rather than a defect in coercion, and the reason it is asserted
here rather than only described is that the failure is silent: Cedar's ``in`` is reflexive, so
a guard reading ``!(context.args.region in Group::"approved")`` is satisfied by passing the
approved group itself, and the result is a clean allow with no engine error. The first test
pins the exposure so nobody mistakes it for safety; the rest pin each defense that closes it.
"""

from __future__ import annotations

from typing import Annotated

import pytest

fastapi = pytest.importorskip("fastapi", reason="the web extra is not installed")

from fastapi import Body, Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import sentrykit  # noqa: E402
from sentrykit import Entity, EntityRef, Principal, protect  # noqa: E402
from sentrykit.constraints import ArgumentConstraint, ConstraintSet  # noqa: E402
from sentrykit.integrations.fastapi import (  # noqa: E402
    FastAPIProvider,
    context_dependency,
    install_error_handlers,
)

PRINCIPAL_HEADER = "x-sentrykit-principal"

UNPINNED_POLICY = """
@id("base")
permit (principal, action, resource);

@id("region-must-be-approved")
forbid (principal, action, resource)
when { context.args has region && !(context.args.region in Group::"approved") };
"""
"""The guard as it reads before the type is pinned — satisfiable by naming the group."""

PINNED_POLICY = """
@id("base")
permit (principal, action, resource);

@id("region-must-be-approved")
forbid (principal, action, resource)
when {
  context.args has region &&
  !(context.args.region is Region && context.args.region in Group::"approved")
};
"""
"""The same guard with Cedar's ``is`` pinning the type, exactly as the concepts page prints."""

ENTITIES = [
    Entity(EntityRef("Group", "approved")),
    Entity(EntityRef("Region", "eu"), parents=(EntityRef("Group", "approved"),)),
    Entity(EntityRef("Region", "cn")),
    Entity(EntityRef("Tool", "orders")),
]

APPROVED_REGION = {"type": "Region", "id": "eu"}
UNAPPROVED_REGION = {"type": "Region", "id": "cn"}
THE_GROUP_ITSELF = {"type": "Group", "id": "approved"}


def _app(policy: str, principal: Principal | None = None) -> tuple[TestClient, list[str]]:
    """Wire one governed route whose ``region`` parameter is an entity reference."""
    ran: list[str] = []
    provider = FastAPIProvider(
        identify=lambda request: (
            principal or Principal(id="alice") if PRINCIPAL_HEADER in request.headers else None
        )
    )
    sentrykit.install(policy, entities=ENTITIES, context_provider=provider)

    app = FastAPI()
    install_error_handlers(app, provider)

    @app.post("/orders", dependencies=[Depends(context_dependency(provider))])
    @protect(action='Action::"tool.search_orders"', resource='Tool::"orders"')
    def search_orders(
        region: Annotated[EntityRef | None, Body(embed=True)] = None,
    ) -> dict[str, object]:
        ran.append(str(region))
        return {"region": str(region)}

    return TestClient(app, raise_server_exceptions=False), ran


def _post(client: TestClient, region: object) -> int:
    response = client.post("/orders", json={"region": region}, headers={PRINCIPAL_HEADER: "alice"})
    return response.status_code


@pytest.mark.integration
def test_a_supplied_escape_mapping_never_reaches_the_evaluator() -> None:
    """The coercion boundary holds: a dict cannot spell its own way into an entity."""
    client, ran = _app(UNPINNED_POLICY)

    status = _post(client, {"__entity": THE_GROUP_ITSELF})

    assert status != 200
    assert ran == []


@pytest.mark.integration
def test_an_unpinned_guard_is_satisfied_by_naming_the_group_itself() -> None:
    """The exposure, stated plainly, because a silent allow is the worst way to learn it.

    The caller picks the entity's type, Cedar's ``in`` is reflexive, and the guard does not
    fire. Nothing in sentrykit can infer that this parameter was not meant to be
    caller-chosen — the annotation says it was.
    """
    client, ran = _app(UNPINNED_POLICY)

    assert _post(client, APPROVED_REGION) == 200
    assert _post(client, UNAPPROVED_REGION) == 403
    assert _post(client, THE_GROUP_ITSELF) == 200
    assert ran == ['Region::"eu"', 'Group::"approved"']


@pytest.mark.integration
def test_pinning_the_type_with_cedars_is_operator_closes_it() -> None:
    client, ran = _app(PINNED_POLICY)

    assert _post(client, APPROVED_REGION) == 200
    assert _post(client, UNAPPROVED_REGION) == 403
    assert _post(client, THE_GROUP_ITSELF) == 403
    assert ran == ['Region::"eu"']


@pytest.mark.integration
def test_bounding_the_argument_with_a_constraint_closes_it_too() -> None:
    """The other defense, and the one that needs no change to the policy text."""
    bounded = Principal(
        id="alice",
        constraints={
            'Action::"tool.search_orders"': ConstraintSet(
                arguments={
                    "region": ArgumentConstraint(
                        allow=(EntityRef("Region", "eu"), EntityRef("Region", "cn")),
                        policy="grant-regions",
                    )
                }
            )
        },
    )
    client, ran = _app(UNPINNED_POLICY, bounded)

    assert _post(client, APPROVED_REGION) == 200
    assert _post(client, THE_GROUP_ITSELF) == 400
    assert ran == ['Region::"eu"']
