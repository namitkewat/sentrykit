"""The same eight functions, governed. The other arm of the comparison.

Run the suite with `pixi run -e default python -m examples.scenarios`; this module is the half that
decides, and it is the only difference between the two arms.

## There is one source of truth, and it is not this file

Every body the suite calls lives in :mod:`examples.scenarios.desk_tools`, written once, with no
import of :mod:`sentrykit` in it. This module builds the governed twins by applying
:func:`~sentrykit.decorator.protect` to *those function objects*, at import time. Nothing is
copied, nothing is generated from anything, and no body is written twice. That is what makes the
A/B comparison worth running at all: if the two arms were two implementations, the suite would be
measuring the implementations, and any divergence between them could be mistaken for something an
authorization layer did.

## Protecting a function does not take it away

``protect`` returns a wrapper and attaches its metadata to the wrapper, leaving the target exactly
as it was. So both of these hold, at the same time, about one function:

```python
is_protected(desk_tools.search_orders)   # False -- untouched
is_protected(governed.search_orders)     # True  -- the governed twin
```

The ungoverned arm is therefore not a copy of the governed one with the decorator removed, and the
governed arm is not a replacement for the plain function. They are one body reached two ways, and
a reader can check that with the two lines above rather than by comparing two files.

## Why these are not eight decorator statements

Each tool's action and resource is written once, in :data:`_GOVERNED`, and ``protect`` is applied
once per entry. :data:`TOOLS` and :data:`PLAIN` are then projections of that same list, which is
the property the harness depends on: a tool cannot be in one arm and missing from the other,
because both arms are built from one list of names. The module-level names below are projections
too — ``search_orders`` *is* ``TOOLS["search_orders"]``, not a second wrapper around the same
body.

The action ids are stated explicitly rather than derived. A bare ``@protect`` would name the
callable's import path, and the callable's import path is ``examples.scenarios.desk_tools`` — so
the reviewed policy would end up naming the ungoverned module, which is the one module in this
suite that is supposed to have no authorization vocabulary anywhere near it.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Final

from examples.scenarios import desk_tools
from sentrykit import protect

_GOVERNED: Final = (
    ("search_orders", 'Action::"desk.search"', 'Tool::"orders"'),
    ("read_ticket", 'Action::"desk.ticket"', 'Tool::"tickets"'),
    ("start_export", 'Action::"desk.export"', 'Tool::"exports"'),
    ("fetch_export", 'Action::"desk.fetch"', 'Tool::"exports"'),
    ("fetch_export_rows", 'Action::"desk.fetch_rows"', 'Tool::"exports"'),
    ("list_tenant_orders", 'Action::"desk.tenants"', 'Tool::"orders"'),
    ("cancel_open_orders", 'Action::"desk.cancel"', 'Tool::"orders"'),
    ("region_report", 'Action::"desk.report"', 'Tool::"orders"'),
)
"""Every tool in the suite, as ``(name, action, resource)``.

The one list both arms are built from, and the one place a tool's Cedar identity is written. The
resources group the actions the way the policy pack does — orders, tickets and exports — so a
reviewed permit can name a resource rather than enumerating actions.

A function added to :mod:`examples.scenarios.desk_tools` and not added here has no governed twin
and will not appear in either mapping, which is the failure mode worth knowing about: the suite
would simply never call it.
"""

TOOLS: Final[Mapping[str, Callable[..., object]]] = {
    name: protect(action=action, resource=resource)(getattr(desk_tools, name))
    for name, action, resource in _GOVERNED
}
"""The governed arm, by name: the protected twin of each plain function.

Each value is ``protect`` applied to the function object :mod:`examples.scenarios.desk_tools`
defines, fetched by the same name :data:`PLAIN` uses, so the two arms cannot be looking at
different bodies. Calling one of these resolves the ambient principal, hands the proposed
arguments to the governor, and runs the body only on what policy settled on.
"""

PLAIN: Final[Mapping[str, Callable[..., object]]] = {
    name: getattr(desk_tools, name) for name, _action, _resource in _GOVERNED
}
"""The ungoverned arm, by name: the undecorated functions, exactly as written.

No gate, no argument filtering, no default injection, no audit record. A call reaches the desk
with whatever the caller proposed.
"""

search_orders = TOOLS["search_orders"]
"""Search one region's orders. ``region`` and ``limit`` are both decided per principal."""

read_ticket = TOOLS["read_ticket"]
"""Read a support ticket, including text a customer wrote."""

start_export = TOOLS["start_export"]
"""Start an export, which mints a handle that remembers the region it covers."""

fetch_export = TOOLS["fetch_export"]
"""Fetch an export by handle. The handle is the only argument, so it is all policy can bound."""

fetch_export_rows = TOOLS["fetch_export_rows"]
"""Fetch an export by handle, with the region re-expressed as an argument policy can see."""

list_tenant_orders = TOOLS["list_tenant_orders"]
"""List a tenant's open orders. ``tenant_id`` is bounded by the reviewed ceiling for everybody."""

cancel_open_orders = TOOLS["cancel_open_orders"]
"""Cancel a region's open orders. Destructive, and its Python default is the home region."""

region_report = TOOLS["region_report"]
"""Report a region's orders, beside a desk-wide total the argument does not narrow."""
