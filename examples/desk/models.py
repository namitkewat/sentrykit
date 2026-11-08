"""The orders desk, as sixteen tables.

Three columns in here carry authorization meaning, and they are the reason the schema looks
the way it does rather than however a support desk would naturally be modelled:

* ``Order.region`` holds ``eu``, ``uk`` and ``us``, the values the example apps' allow-sets
  and defaults are written against. A narrowed ``region`` has to select a *different set of
  rows*, which it only does if more than one value is present in quantity.
* ``Order.status`` holds ``open``, ``closed`` and ``cancelled``. ``open`` is the policy
  default, so it has to be the status a caller lands on when they name none.
* ``Order.id`` is formatted ``ord-NNNN``, because a shipped grant constrains ``order_id``
  with the pattern ``ord-[0-9]{4}`` and an id that fails it is dropped rather than queried.
  ``Refund.id`` reads ``rf-NNNN`` and ``ExportJob.id`` reads ``exp-NNNN`` for the same
  reason: a handle a policy can describe.

Money is stored as a whole number of minor units — cents, pence — so that no total in the
examples' printed output depends on binary floating point. ``Order`` carries no stored total
at all: it is summed from the line items and their products on read, which is what makes an
order's total a genuine four-table join rather than a column lookup.

Timestamps are naive and understood as UTC. SQLite has no timezone type, so a naive column is
the honest representation of what is on disk, and :mod:`examples.desk.queries` re-attaches UTC
at the boundary where a timestamp becomes a string.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base shared by every desk table.

    Exported so a caller can create or drop the whole schema through one metadata object
    without importing sixteen classes to do it.
    """


class Tenant(Base):
    """A customer of the desk's operator, and the root of the entity hierarchy.

    ``desk`` is the name the desk answers to. It lives in data rather than in a literal so
    that renaming the desk is an update rather than an edit, which is the same split the
    library draws between reviewed policy and mutable grants.
    """

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    desk: Mapped[str] = mapped_column(String(32))
    plan: Mapped[str] = mapped_column(String(16))

    teams: Mapped[list[Team]] = relationship(back_populates="tenant")


class Team(Base):
    """A group of agents inside one tenant, and the middle hop of the hierarchy.

    ``region`` is the region the team covers, which is not the same question as the region an
    order is booked in: an agent on the EU team can be looking at a US order, and whether
    they may is the policy layer's business rather than this column's.
    """

    __tablename__ = "teams"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    name: Mapped[str] = mapped_column(String(80))
    region: Mapped[str] = mapped_column(String(8))

    tenant: Mapped[Tenant] = relationship(back_populates="teams")
    memberships: Mapped[list[UserTeam]] = relationship(back_populates="team")


class User(Base):
    """An agent on the desk.

    ``role`` is denormalised onto the user because the examples' grant stores read it when
    they seed a principal, and a desk with one role per person is the common case. A user who
    needs two roles gets them from the grant store, not from a second column here.
    """

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    display_name: Mapped[str] = mapped_column(String(80))
    email: Mapped[str] = mapped_column(String(120))
    role: Mapped[str] = mapped_column(String(16))

    memberships: Mapped[list[UserTeam]] = relationship(back_populates="user")


class UserTeam(Base):
    """One user's membership of one team.

    A table rather than a pair of columns on ``users``, because the hierarchy the policies
    walk allows a person to sit under more than one team at once — and because a membership
    is the kind of thing that acquires an expiry or a grantor later without a migration of
    anything else.
    """

    __tablename__ = "user_teams"

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True)
    team_id: Mapped[str] = mapped_column(ForeignKey("teams.id"), primary_key=True)
    is_lead: Mapped[bool] = mapped_column(Boolean, default=False)

    user: Mapped[User] = relationship(back_populates="memberships")
    team: Mapped[Team] = relationship(back_populates="memberships")


class Customer(Base):
    """Whoever placed the orders. Not a principal: nobody authorizes as a customer."""

    __tablename__ = "customers"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    name: Mapped[str] = mapped_column(String(80))
    email: Mapped[str] = mapped_column(String(120))
    region: Mapped[str] = mapped_column(String(8))

    addresses: Mapped[list[Address]] = relationship(back_populates="customer")
    orders: Mapped[list[Order]] = relationship(back_populates="customer")


class Address(Base):
    """Where one customer's orders go.

    A customer may have several, so an order names the one it shipped to rather than
    inheriting a single address from the customer — which is what turns reading one order
    into a join instead of a lookup.
    """

    __tablename__ = "addresses"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    customer_id: Mapped[str] = mapped_column(ForeignKey("customers.id"))
    line1: Mapped[str] = mapped_column(String(120))
    city: Mapped[str] = mapped_column(String(80))
    postcode: Mapped[str] = mapped_column(String(16))
    country: Mapped[str] = mapped_column(String(2))
    region: Mapped[str] = mapped_column(String(8))
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False)

    customer: Mapped[Customer] = relationship(back_populates="addresses")


class Product(Base):
    """What the desk sells. ``price`` is the single source of a line item's money."""

    __tablename__ = "products"

    sku: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    category: Mapped[str] = mapped_column(String(32))
    price: Mapped[int] = mapped_column(Integer)
    active: Mapped[bool] = mapped_column(Boolean, default=True)

    items: Mapped[list[OrderItem]] = relationship(back_populates="product")
    inventory: Mapped[list[InventoryLevel]] = relationship(back_populates="product")


class InventoryLevel(Base):
    """How much of one product sits in one warehouse.

    Stock is per warehouse rather than per product because a region's availability is the
    question an agent actually asks, and the answer differs by region.
    """

    __tablename__ = "inventory_levels"
    __table_args__ = (UniqueConstraint("sku", "warehouse", name="uq_inventory_sku_warehouse"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sku: Mapped[str] = mapped_column(ForeignKey("products.sku"))
    warehouse: Mapped[str] = mapped_column(String(32))
    region: Mapped[str] = mapped_column(String(8))
    on_hand: Mapped[int] = mapped_column(Integer)
    reserved: Mapped[int] = mapped_column(Integer)

    product: Mapped[Product] = relationship(back_populates="inventory")


class Order(Base):
    """One order, and the row every policy in the examples is ultimately about.

    ``region`` and ``status`` are the two governed columns, and ``id`` is the governed
    handle. There is deliberately no ``total``: summing the line items on read keeps one
    answer rather than two that can disagree, and it is why reading an order touches
    ``orders``, ``customers``, ``order_items`` and ``products`` at once.
    """

    __tablename__ = "orders"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    customer_id: Mapped[str] = mapped_column(ForeignKey("customers.id"))
    address_id: Mapped[str] = mapped_column(ForeignKey("addresses.id"))
    owner_team_id: Mapped[str] = mapped_column(ForeignKey("teams.id"))
    region: Mapped[str] = mapped_column(String(8), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)
    channel: Mapped[str] = mapped_column(String(16))
    placed_at: Mapped[datetime] = mapped_column(DateTime)

    customer: Mapped[Customer] = relationship(back_populates="orders")
    address: Mapped[Address] = relationship()
    items: Mapped[list[OrderItem]] = relationship(back_populates="order")
    shipment: Mapped[Shipment | None] = relationship(back_populates="order")
    payments: Mapped[list[Payment]] = relationship(back_populates="order")
    refunds: Mapped[list[Refund]] = relationship(back_populates="order")


class OrderItem(Base):
    """One line of one order. Carries the quantity; the money comes from the product."""

    __tablename__ = "order_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    order_id: Mapped[str] = mapped_column(ForeignKey("orders.id"), index=True)
    sku: Mapped[str] = mapped_column(ForeignKey("products.sku"))
    quantity: Mapped[int] = mapped_column(Integer)

    order: Mapped[Order] = relationship(back_populates="items")
    product: Mapped[Product] = relationship(back_populates="items")


class Shipment(Base):
    """The parcel for one order, where there is one. At most one per order."""

    __tablename__ = "shipments"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    order_id: Mapped[str] = mapped_column(ForeignKey("orders.id"), unique=True)
    carrier: Mapped[str] = mapped_column(String(32))
    tracking: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16))
    shipped_at: Mapped[datetime] = mapped_column(DateTime)

    order: Mapped[Order] = relationship(back_populates="shipment")


class Payment(Base):
    """Money in. Paired with :class:`Refund`, which is money back out again."""

    __tablename__ = "payments"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    order_id: Mapped[str] = mapped_column(ForeignKey("orders.id"), index=True)
    amount: Mapped[int] = mapped_column(Integer)
    method: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16))
    captured_at: Mapped[datetime] = mapped_column(DateTime)

    order: Mapped[Order] = relationship(back_populates="payments")


class Refund(Base):
    """Money back out, and the one row in the schema that two calls share.

    A refund is written ``pending`` and approved later, by a different principal under a
    different policy. That gap is the point: it is what lets the examples show one call that
    may create the row and another that may settle it, against the same data.
    """

    __tablename__ = "refunds"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    order_id: Mapped[str] = mapped_column(ForeignKey("orders.id"), index=True)
    amount: Mapped[int] = mapped_column(Integer)
    region: Mapped[str] = mapped_column(String(8))
    status: Mapped[str] = mapped_column(String(16), index=True)
    reason: Mapped[str] = mapped_column(String(80))
    requested_by: Mapped[str] = mapped_column(String(32))
    approved_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)

    order: Mapped[Order] = relationship(back_populates="refunds")


class Ticket(Base):
    """A customer's conversation with the desk."""

    __tablename__ = "tickets"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    customer_id: Mapped[str] = mapped_column(ForeignKey("customers.id"))
    order_id: Mapped[str | None] = mapped_column(ForeignKey("orders.id"), nullable=True)
    assigned_to: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    subject: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(16), index=True)
    region: Mapped[str] = mapped_column(String(8))
    created_at: Mapped[datetime] = mapped_column(DateTime)

    customer: Mapped[Customer] = relationship()
    messages: Mapped[list[TicketMessage]] = relationship(
        back_populates="ticket", order_by="TicketMessage.created_at"
    )


class TicketMessage(Base):
    """One message in a ticket, from either side of the desk.

    ``author`` is an id and ``author_role`` says which table it belongs to — a customer or a
    user — rather than a foreign key to one of them, because the author of a message is often
    neither: an automated reply, a forwarded mail, a note from a carrier. The body is
    free text a stranger wrote, and the desk treats it as data.
    """

    __tablename__ = "ticket_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id"), index=True)
    author: Mapped[str] = mapped_column(String(32))
    author_role: Mapped[str] = mapped_column(String(16))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime)

    ticket: Mapped[Ticket] = relationship(back_populates="messages")


class ExportJob(Base):
    """An export, recorded so that its id can be presented back later.

    The row exists to be a *handle*: one call creates it and hands out ``id``, and a later
    call quotes that id to read the export. It therefore records the ``region``, ``scope`` and
    ``fmt`` the export was created for and the user who asked — everything needed to ask
    whether a second call presenting this handle is still inside the narrowing the first one
    was subject to.
    """

    __tablename__ = "export_jobs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    fmt: Mapped[str] = mapped_column(String(16))
    scope: Mapped[str] = mapped_column(String(16))
    region: Mapped[str] = mapped_column(String(8))
    rows: Mapped[int] = mapped_column(Integer)
    requested_by: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime)
