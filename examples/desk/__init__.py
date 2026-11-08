"""The orders desk: a small, seeded SQLite database for the example apps to query.

The examples exist to show what an authorization layer does to a call, and the thing hardest
to show convincingly is *narrowing*. A function that echoes its own arguments back can only
report that it was given ``region="eu"``; it cannot show that asking for a region you are not
entitled to leaves you looking at a smaller, different set of real rows. So the desk is a real
database — sixteen tables, a few thousand rows, joins that span four of them — and the
governed functions in the example apps read from it.

Three properties are load-bearing, and each has a test holding it still:

* **Deterministic.** One fixed seed and one fixed clock produce the same rows on every machine
  and every run, so a printed table can be asserted on and a documented order id stays valid.
* **In memory by default.** Nothing is left on disk unless ``SENTRYKIT_DEMO_DB`` names a file,
  and the in-memory engine is deliberately built to be one shared database rather than one
  per thread -- see :mod:`examples.desk.database` for why that is not the default.
* **Idempotent setup.** :func:`ensure_desk` can be called at import time, by every app, on
  every query, and the second call does nothing.

The desk knows nothing about authorization: it does not import the library, take a principal,
or ask whether a call is permitted. It is the domain layer the governed functions happen to
call, which is exactly the separation an application should be able to keep.

Start with :func:`ensure_desk`, then the functions in :mod:`examples.desk.queries`. For
anything the query surface does not cover, :func:`session_scope` hands out a session.
"""

from __future__ import annotations

from examples.desk.database import (
    DB_URL_ENV,
    IN_MEMORY_URL,
    close_desk,
    database_url,
    engine,
    ensure_desk,
    reset_desk,
    session_scope,
)
from examples.desk.models import (
    Address,
    Base,
    Customer,
    ExportJob,
    InventoryLevel,
    Order,
    OrderItem,
    Payment,
    Product,
    Refund,
    Shipment,
    Team,
    Tenant,
    Ticket,
    TicketMessage,
    User,
    UserTeam,
)
from examples.desk.queries import (
    UnknownOrder,
    approve_refund,
    desk_counts,
    export_job,
    find_orders,
    order_brief,
    order_detail,
    order_summary,
    record_refund,
    start_export,
    ticket_thread,
)
from examples.desk.seed import DESK_TENANT, RANDOM_SEED, REGIONS, seed_desk

__all__ = [
    "DB_URL_ENV",
    "DESK_TENANT",
    "IN_MEMORY_URL",
    "RANDOM_SEED",
    "REGIONS",
    "Address",
    "Base",
    "Customer",
    "ExportJob",
    "InventoryLevel",
    "Order",
    "OrderItem",
    "Payment",
    "Product",
    "Refund",
    "Shipment",
    "Team",
    "Tenant",
    "Ticket",
    "TicketMessage",
    "UnknownOrder",
    "User",
    "UserTeam",
    "approve_refund",
    "close_desk",
    "database_url",
    "desk_counts",
    "engine",
    "ensure_desk",
    "export_job",
    "find_orders",
    "order_brief",
    "order_detail",
    "order_summary",
    "record_refund",
    "reset_desk",
    "seed_desk",
    "session_scope",
    "start_export",
    "ticket_thread",
]
