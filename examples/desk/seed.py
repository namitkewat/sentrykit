"""The desk's data, generated the same way on every machine.

Everything here is driven by one :class:`random.Random` seeded with a constant, and by one
fixed clock. That is not a stylistic preference: the example apps print tables of real query
results, and a table nobody can predict is a table nobody can assert on. Re-seed twice and you
get the same rows; seed on another machine and you get the same rows; so a documented output
and a test expectation can both name an actual order id.

No third-party data generator is involved, for the same reason the core keeps few
dependencies — the word pools below are shorter than the argument for installing something to
produce them.

**The clock.** Rows are dated by their own sequence number rather than by the wall clock:
``ord-0042`` is dated as the forty-second step after :data:`DESK_EPOCH`. Reading a row's date
therefore needs nothing but its id, which keeps a timestamp printed by an example stable
across runs — including on the rows a *running* app inserts, where ``datetime.now`` would
otherwise put an unassertable value into the output. The dates are shuffled against the ids so
that "the oldest open order" is a real question about a date column rather than a restatement
of "the lowest id".

The distributions are chosen so that the governed columns actually bite. There are enough
``eu``/``open`` orders that a limit of 3, a limit of 25 and a limit above the whole result set
are three visibly different answers, and enough orders booked outside their customer's own
region that a rule about region and amount together has something to fire on.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from examples.desk.models import (
    Address,
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

RANDOM_SEED = 20260301
"""The one constant the whole generator hangs off. Changing it changes every row."""

DESK_EPOCH = datetime(2026, 1, 5, 9, 0)
"""Naive UTC. The instant sequence number zero refers to."""

CLOCK_STEP = timedelta(hours=6)
"""How far apart two consecutive sequence numbers are."""

DESK_TENANT = "acme"
"""The tenant whose desk this is. Its ``desk`` column names the desk the queries report."""

ORDER_COUNT = 400
"""Orders. Large enough that a narrowed ``limit`` and a wide one differ visibly."""

CUSTOMER_COUNT = 40
PRODUCT_COUNT = 24
TICKET_COUNT = 26
REFUND_COUNT = 14
PENDING_REFUND_COUNT = 4
"""The first few refunds are left ``pending`` so that an approval has something to approve."""

REGIONS = ("eu", "uk", "us")
"""The values the examples' allow-sets and defaults are written against."""

_REGION_WEIGHTS = (42, 26, 32)
_STATUSES = ("open", "closed", "cancelled")
_STATUS_WEIGHTS = (46, 44, 10)
_CHANNELS = ("web", "phone", "partner")

_WAREHOUSES = (("ware-eu-1", "eu"), ("ware-uk-1", "uk"), ("ware-us-1", "us"))

_FIRST_NAMES = (
    "Ada", "Bruno", "Celine", "Dmitri", "Elena", "Farid", "Greta", "Hugo",
    "Ingrid", "Jonas", "Katya", "Liam", "Marta", "Niall", "Olga", "Pedro",
    "Quinn", "Rosa", "Stefan", "Tamara",
)  # fmt: skip
_LAST_NAMES = (
    "Abelard", "Brandt", "Caruso", "Dahl", "Eriksen", "Fontaine", "Gallo",
    "Haas", "Ivanov", "Jensen", "Kovacs", "Lindqvist", "Moreau", "Novak",
    "Olsen", "Pires", "Rossi", "Svensson", "Tveit", "Vogel",
)  # fmt: skip
_CITIES = {
    "eu": (("Berlin", "DE"), ("Lyon", "FR"), ("Utrecht", "NL"), ("Porto", "PT")),
    "uk": (("Leeds", "GB"), ("Bristol", "GB"), ("Glasgow", "GB"), ("Cardiff", "GB")),
    "us": (("Austin", "US"), ("Portland", "US"), ("Omaha", "US"), ("Tampa", "US")),
}
_STREETS = ("Mill Lane", "Harbour Road", "Station Street", "Kiln Walk", "Foundry Row")

_PRODUCT_WORDS = (
    "Desk Lamp", "Cable Tidy", "Monitor Arm", "Laptop Stand", "Keyboard Tray",
    "Footrest", "Task Chair", "Filing Caddy", "Pin Board", "Whiteboard",
    "Label Maker", "Paper Guillotine", "Stapler", "Hole Punch", "Pen Cup",
    "Desk Mat", "Wrist Rest", "Headset Hook", "Drawer Insert", "Shelf Riser",
    "Cable Clip", "Screen Filter", "Document Holder", "Charging Dock",
)  # fmt: skip
_CATEGORIES = ("lighting", "storage", "ergonomics", "stationery")

_TICKET_SUBJECTS = (
    "Where is my parcel?",
    "Wrong item delivered",
    "Refund not received",
    "Damaged on arrival",
    "Change delivery address",
    "Invoice query",
    "Cancel my order",
    "Missing part",
)
_CUSTOMER_LINES = (
    "This still has not arrived and the tracking page has not moved in days.",
    "The box turned up open and one of the parts is missing.",
    "Could you confirm in writing what was refunded and when?",
    "I would like to change the delivery address before it ships.",
    "Nobody has come back to me on this since last week.",
)
_AGENT_LINES = (
    "Thanks for getting in touch -- I can see the order and I am checking with the carrier.",
    "I have raised this with the warehouse and will update you once they reply.",
    "A replacement is on its way and you do not need to return the original.",
    "I have requested the refund; it takes a few days to reach the card.",
    "Apologies for the wait. I have escalated this to the team lead.",
)
_REFUND_REASONS = (
    "damaged in transit",
    "wrong item",
    "never arrived",
    "duplicate charge",
    "cancelled after dispatch",
)


def stamp(sequence: int) -> datetime:
    """Return the desk's date for a row with sequence number ``sequence``.

    Args:
        sequence: The numeric part of a row's id -- 42 for ``ord-0042``.

    Returns:
        A naive UTC datetime, understood as UTC by everything that reads it.
    """
    return DESK_EPOCH + sequence * CLOCK_STEP


def seed_desk(session: Session) -> None:
    """Fill every table, assuming they are empty.

    Does not commit: the caller decides when the transaction closes, which is what lets a
    test seed two engines and compare them without either being half-written.

    Args:
        session: A session on an empty, already-created schema.
    """
    rng = random.Random(RANDOM_SEED)

    _seed_tenants(session)
    teams = _seed_teams(session)
    _seed_users_and_memberships(session)
    products = _seed_products(session, rng)
    _seed_inventory(session, products, rng)
    customers = _seed_customers(session, rng)
    addresses = _seed_addresses(session, customers, rng)
    orders = _seed_orders(session, customers, addresses, teams, rng)
    _seed_order_items(session, orders, products, rng)
    _seed_shipments(session, orders, rng)
    _seed_payments(session, orders, products, rng)
    _seed_refunds(session, orders, rng)
    tickets = _seed_tickets(session, customers, orders, rng)
    _seed_ticket_messages(session, tickets, rng)
    _seed_export_jobs(session, orders)


def _seed_tenants(session: Session) -> None:
    """Write the two tenants: the desk's own, and a second root for the hierarchy.

    A second root exists so that "the top of the hierarchy" is a column with more than one
    value in it. Both run an orders desk; only the first one's name is what the queries
    report.
    """
    session.add_all(
        [
            Tenant(id=DESK_TENANT, name="Acme Supplies", desk="orders", plan="enterprise"),
            Tenant(id="globex", name="Globex Trading", desk="orders", plan="standard"),
        ]
    )
    session.flush()


def _seed_teams(session: Session) -> dict[str, list[Team]]:
    """Write the teams, and return them indexed by tenant so an order can find its owner."""
    teams = [
        Team(id="eu-support", tenant_id=DESK_TENANT, name="EU Support", region="eu"),
        Team(id="uk-support", tenant_id=DESK_TENANT, name="UK Support", region="uk"),
        Team(id="us-support", tenant_id=DESK_TENANT, name="US Support", region="us"),
        Team(id="apac-support", tenant_id="globex", name="APAC Support", region="us"),
    ]
    session.add_all(teams)
    session.flush()
    by_tenant: dict[str, list[Team]] = {}
    for team in teams:
        by_tenant.setdefault(team.tenant_id, []).append(team)
    return by_tenant


def _seed_users_and_memberships(session: Session) -> None:
    """Write the agents, and put two of them on more than one team.

    The ids match the principals the example policies name, so the hierarchy the policies
    walk and the rows an app queries describe the same desk. Alice and Dana sit under two
    teams each, which is the case a single column on ``users`` could not express.
    """
    users = [
        User(
            id="alice",
            tenant_id=DESK_TENANT,
            display_name="Alice Nwosu",
            email="alice@acme.example",
            role="support",
        ),
        User(
            id="bob",
            tenant_id=DESK_TENANT,
            display_name="Bob Lindgren",
            email="bob@acme.example",
            role="auditor",
        ),
        User(
            id="carol",
            tenant_id=DESK_TENANT,
            display_name="Carol Mensah",
            email="carol@acme.example",
            role="support",
        ),
        User(
            id="dana",
            tenant_id=DESK_TENANT,
            display_name="Dana Reyes",
            email="dana@acme.example",
            role="admin",
        ),
        User(
            id="erin",
            tenant_id="globex",
            display_name="Erin Okafor",
            email="erin@globex.example",
            role="support",
        ),
        User(
            id="frank",
            tenant_id="globex",
            display_name="Frank Adeyemi",
            email="frank@globex.example",
            role="auditor",
        ),
    ]
    session.add_all(users)
    session.flush()

    memberships = [
        UserTeam(user_id="alice", team_id="eu-support", is_lead=True),
        UserTeam(user_id="alice", team_id="uk-support", is_lead=False),
        UserTeam(user_id="bob", team_id="us-support", is_lead=False),
        UserTeam(user_id="carol", team_id="us-support", is_lead=True),
        UserTeam(user_id="dana", team_id="eu-support", is_lead=False),
        UserTeam(user_id="dana", team_id="us-support", is_lead=False),
        UserTeam(user_id="erin", team_id="apac-support", is_lead=True),
        UserTeam(user_id="frank", team_id="apac-support", is_lead=False),
    ]
    session.add_all(memberships)
    session.flush()


def _seed_products(session: Session, rng: random.Random) -> list[Product]:
    """Write the catalogue. Price is in minor units, so no total is ever a float."""
    products = [
        Product(
            sku=f"sku-{index:04d}",
            name=_PRODUCT_WORDS[index - 1],
            category=_CATEGORIES[index % len(_CATEGORIES)],
            price=rng.randrange(450, 18_000, 50),
            active=index % 12 != 0,
        )
        for index in range(1, PRODUCT_COUNT + 1)
    ]
    session.add_all(products)
    session.flush()
    return products


def _seed_inventory(session: Session, products: list[Product], rng: random.Random) -> None:
    """Stock every product in every warehouse, at a different level in each."""
    levels = [
        InventoryLevel(
            sku=product.sku,
            warehouse=warehouse,
            region=region,
            on_hand=rng.randrange(0, 400),
            reserved=rng.randrange(0, 40),
        )
        for product in products
        for warehouse, region in _WAREHOUSES
    ]
    session.add_all(levels)
    session.flush()


def _seed_customers(session: Session, rng: random.Random) -> list[Customer]:
    """Write the customers, mostly under the desk's own tenant."""
    customers: list[Customer] = []
    for index in range(1, CUSTOMER_COUNT + 1):
        first = _FIRST_NAMES[(index * 7) % len(_FIRST_NAMES)]
        last = _LAST_NAMES[(index * 11) % len(_LAST_NAMES)]
        region = rng.choices(REGIONS, weights=_REGION_WEIGHTS, k=1)[0]
        customers.append(
            Customer(
                id=f"cus-{index:04d}",
                tenant_id=DESK_TENANT if index % 7 else "globex",
                name=f"{first} {last}",
                email=f"{first.lower()}.{last.lower()}@mail.example",
                region=region,
            )
        )
    session.add_all(customers)
    session.flush()
    return customers


def _seed_addresses(
    session: Session, customers: list[Customer], rng: random.Random
) -> dict[str, list[Address]]:
    """Give each customer one address, and every third customer a second one."""
    addresses: list[Address] = []
    by_customer: dict[str, list[Address]] = {}
    counter = 0
    for position, customer in enumerate(customers, start=1):
        for slot in range(2 if position % 3 == 0 else 1):
            counter += 1
            city, country = rng.choice(_CITIES[customer.region])
            address = Address(
                id=f"adr-{counter:04d}",
                customer_id=customer.id,
                line1=f"{rng.randrange(1, 180)} {rng.choice(_STREETS)}",
                city=city,
                postcode=f"{rng.randrange(10_000, 99_999)}",
                country=country,
                region=customer.region,
                is_primary=slot == 0,
            )
            addresses.append(address)
            by_customer.setdefault(customer.id, []).append(address)
    session.add_all(addresses)
    session.flush()
    return by_customer


def _seed_orders(
    session: Session,
    customers: list[Customer],
    addresses: dict[str, list[Address]],
    teams: dict[str, list[Team]],
    rng: random.Random,
) -> list[Order]:
    """Write the order book.

    Two choices here are deliberate. An order is usually booked in its customer's own region
    and sometimes is not, so a rule about region and amount together has rows to fire on. And
    the dates are shuffled against the ids, so the oldest open order is not simply the
    lowest-numbered one and a query that claims to find it has to read the date.
    """
    dates = [stamp(sequence) for sequence in range(1, ORDER_COUNT + 1)]
    rng.shuffle(dates)

    orders: list[Order] = []
    for index in range(1, ORDER_COUNT + 1):
        customer = rng.choice(customers)
        region = (
            customer.region
            if rng.random() < 0.85
            else rng.choice([other for other in REGIONS if other != customer.region])
        )
        tenant_teams = teams[customer.tenant_id]
        owner = next((team for team in tenant_teams if team.region == region), tenant_teams[0])
        orders.append(
            Order(
                id=f"ord-{index:04d}",
                tenant_id=customer.tenant_id,
                customer_id=customer.id,
                address_id=rng.choice(addresses[customer.id]).id,
                owner_team_id=owner.id,
                region=region,
                status=rng.choices(_STATUSES, weights=_STATUS_WEIGHTS, k=1)[0],
                channel=rng.choice(_CHANNELS),
                placed_at=dates[index - 1],
            )
        )
    session.add_all(orders)
    session.flush()
    return orders


def _seed_order_items(
    session: Session, orders: list[Order], products: list[Product], rng: random.Random
) -> None:
    """Give every order between one and four distinct lines."""
    items: list[OrderItem] = []
    for order in orders:
        for product in rng.sample(products, rng.randint(1, 4)):
            items.append(OrderItem(order_id=order.id, sku=product.sku, quantity=rng.randint(1, 5)))
    session.add_all(items)
    session.flush()


def _seed_shipments(session: Session, orders: list[Order], rng: random.Random) -> None:
    """Ship every closed order, and some of the open ones. Never a cancelled one."""
    shipments: list[Shipment] = []
    counter = 0
    for order in orders:
        if order.status == "cancelled":
            continue
        if order.status == "open" and rng.random() > 0.4:
            continue
        counter += 1
        shipments.append(
            Shipment(
                id=f"shp-{counter:04d}",
                order_id=order.id,
                carrier=rng.choice(("Parcelforce", "DHL", "GLS", "UPS")),
                tracking=f"TRK{rng.randrange(10_000_000, 99_999_999)}",
                status="delivered" if order.status == "closed" else "in_transit",
                shipped_at=order.placed_at + timedelta(days=2),
            )
        )
    session.add_all(shipments)
    session.flush()


def _seed_payments(
    session: Session, orders: list[Order], products: list[Product], rng: random.Random
) -> None:
    """Take one payment per order that was not cancelled.

    The amount is drawn rather than summed from the lines: a payment is what was actually
    charged, and an order whose payment and line total disagree is exactly the kind of row a
    support desk exists to look at.
    """
    prices = [product.price for product in products]
    payments: list[Payment] = []
    counter = 0
    for order in orders:
        if order.status == "cancelled":
            continue
        counter += 1
        payments.append(
            Payment(
                id=f"pay-{counter:04d}",
                order_id=order.id,
                amount=rng.choice(prices) * rng.randint(1, 6),
                method=rng.choice(("card", "invoice", "transfer")),
                status="captured" if order.status == "closed" else "authorized",
                captured_at=order.placed_at + timedelta(hours=1),
            )
        )
    session.add_all(payments)
    session.flush()


def _seed_refunds(session: Session, orders: list[Order], rng: random.Random) -> None:
    """Write a handful of refunds against closed orders, the first few still pending.

    Pending ones matter more than approved ones: an approval needs something to approve, and
    the id of the first pending refund is what an example quotes.
    """
    closed = [order for order in orders if order.status == "closed"]
    chosen = sorted(rng.sample(closed, REFUND_COUNT), key=lambda order: order.id)
    refunds: list[Refund] = []
    for position, order in enumerate(chosen, start=1):
        pending = position <= PENDING_REFUND_COUNT
        refunds.append(
            Refund(
                id=f"rf-{position:04d}",
                order_id=order.id,
                amount=rng.randrange(500, 9_000, 50),
                region=order.region,
                status="pending" if pending else "approved",
                reason=rng.choice(_REFUND_REASONS),
                requested_by=rng.choice(("alice", "carol")),
                approved_by=None if pending else "dana",
                created_at=stamp(position),
            )
        )
    session.add_all(refunds)
    session.flush()


def _seed_tickets(
    session: Session, customers: list[Customer], orders: list[Order], rng: random.Random
) -> list[Ticket]:
    """Open conversations, most of them about an order."""
    tickets: list[Ticket] = []
    for index in range(1, TICKET_COUNT + 1):
        customer = customers[(index * 5) % len(customers)]
        customer_orders = [order for order in orders if order.customer_id == customer.id]
        order = rng.choice(customer_orders) if customer_orders and index % 4 else None
        tickets.append(
            Ticket(
                id=f"tkt-{index:04d}",
                customer_id=customer.id,
                order_id=order.id if order is not None else None,
                assigned_to=rng.choice(("alice", "carol", "dana")),
                subject=_TICKET_SUBJECTS[index % len(_TICKET_SUBJECTS)],
                status="open" if index % 3 else "closed",
                region=customer.region,
                created_at=stamp(index * 3),
            )
        )
    session.add_all(tickets)
    session.flush()
    return tickets


def _seed_ticket_messages(session: Session, tickets: list[Ticket], rng: random.Random) -> None:
    """Fill each thread, customer first and the two sides alternating after that.

    The customer's id goes in ``author``, not a user's, which is the case this table is shaped
    for: most of the text on a ticket was written by somebody outside the desk entirely.
    """
    messages: list[TicketMessage] = []
    for ticket in tickets:
        for turn in range(rng.randint(2, 5)):
            from_customer = turn % 2 == 0
            messages.append(
                TicketMessage(
                    ticket_id=ticket.id,
                    author=ticket.customer_id if from_customer else (ticket.assigned_to or "desk"),
                    author_role="customer" if from_customer else "agent",
                    body=rng.choice(_CUSTOMER_LINES if from_customer else _AGENT_LINES),
                    created_at=ticket.created_at + turn * timedelta(hours=3),
                )
            )
    session.add_all(messages)
    session.flush()


def _seed_export_jobs(session: Session, orders: list[Order]) -> None:
    """Record a few exports that have already been run.

    Seeded so that an example can read a handle back without having to create one first, and
    so the table is not empty the first time somebody looks at it.
    """
    jobs = [
        ("csv", "open", "eu", "alice"),
        ("csv", "all", "uk", "dana"),
        ("json", "closed", "us", "bob"),
    ]
    rows = [
        ExportJob(
            id=f"exp-{position:04d}",
            fmt=fmt,
            scope=scope,
            region=region,
            rows=sum(
                1
                for order in orders
                if order.region == region and (scope == "all" or order.status == scope)
            ),
            requested_by=requested_by,
            created_at=stamp(position),
        )
        for position, (fmt, scope, region, requested_by) in enumerate(jobs, start=1)
    ]
    session.add_all(rows)
    session.flush()
