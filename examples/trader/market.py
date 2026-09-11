"""What the agent is allowed to know about the world.

Two sources, and the difference between them is the point.

The **book and the balances** come straight off the ledger over JSON-RPC —
``book_offers`` in both directions, ``account_info`` for XRP, ``account_lines``
for the issued side. Nothing is quoted to the agent that a stranger could not
re-read from a public node a minute later.

The **reference price** comes from one endpoint on the internet, named in the
config, and is treated accordingly: it is labelled with its source, it is
allowed to be missing, and a cycle where it is missing still runs. An agent that
stopped trading because a price API returned 503 would be an agent whose
solvency depends on somebody else's uptime.

Every number here is a :class:`~decimal.Decimal` from the moment it is read.
The JSON is parsed with ``parse_float=Decimal`` rather than through a rail
client, because ``0.1 + 0.2`` is a bug in a payments system and the cheapest
place to prevent it is the first parse. Nothing in this module ever builds a
``float``.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Sequence
from decimal import Decimal, InvalidOperation
from typing import Any, Final

import httpx

from merkl.adapters.xrpl import currency_code
from merkl.core.canonical import JSONObject, format_decimal

DROPS_PER_XRP: Final = Decimal(1_000_000)
PRICE_PLACES: Final = Decimal("0.000001")
BOOK_LIMIT: Final = 40
DEFAULT_TIMEOUT: Final = 20.0

XRP: Final = "XRP"


class MarketError(Exception):
    """The ledger could not be read. A missing reference price is not one of these."""


# -- the snapshot ----------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class Level:
    """One rung of the book: what ``size`` of the base asset actually costs."""

    size: Decimal
    filled: Decimal
    price: Decimal | None
    """Quote per unit of base, volume-weighted over the fill. ``None`` when the
    book could not fill any of it."""

    def to_content(self) -> JSONObject:
        return {
            "size": format_decimal(self.size),
            "filled": format_decimal(self.filled),
            "price": None if self.price is None else format_decimal(self.price),
        }


@dataclasses.dataclass(frozen=True)
class Book:
    best_bid: Decimal | None
    best_ask: Decimal | None
    mid: Decimal | None
    spread: Decimal | None
    buy_depth: tuple[Level, ...]
    sell_depth: tuple[Level, ...]

    def to_content(self) -> JSONObject:
        return {
            "best_bid": _opt(self.best_bid),
            "best_ask": _opt(self.best_ask),
            "mid": _opt(self.mid),
            "spread": _opt(self.spread),
            "cost_to_buy_base": [level.to_content() for level in self.buy_depth],
            "proceeds_selling_base": [level.to_content() for level in self.sell_depth],
        }


@dataclasses.dataclass(frozen=True)
class Reference:
    source: str
    price: Decimal | None
    error: str = ""

    def to_content(self) -> JSONObject:
        return {"source": self.source, "price_usd": _opt(self.price), "error": self.error}


@dataclasses.dataclass(frozen=True)
class Snapshot:
    """Everything the model is shown about the outside world."""

    as_of: str
    base: str
    quote: str
    balances: dict[str, Decimal]
    book: Book
    reference: Reference

    def to_content(self) -> JSONObject:
        return {
            "as_of": self.as_of,
            "pair": f"{self.base}/{self.quote}",
            "prices_are": f"{self.quote} per 1 {self.base}",
            "balances": {code: format_decimal(value) for code, value in self.balances.items()},
            "book": self.book.to_content(),
            "reference": self.reference.to_content(),
        }

    def balance(self, code: str) -> Decimal:
        return self.balances.get(code, Decimal(0))


# -- reading it ------------------------------------------------------------- #


class MarketReader:
    """One treasury, one pair, one public node."""

    def __init__(
        self,
        *,
        json_rpc_url: str,
        treasury: str,
        base: str,
        quote_code: str,
        quote_issuer: str,
        depths: Sequence[Decimal],
        reference_url: str,
        reference_path: Sequence[str],
        reference_source: str,
        client: httpx.AsyncClient | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._url = json_rpc_url
        self._treasury = treasury
        self._base = base
        self._quote_code = quote_code
        self._quote_issuer = quote_issuer
        self._depths = tuple(depths)
        self._reference_url = reference_url
        self._reference_path = tuple(reference_path)
        self._reference_source = reference_source
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    @property
    def quote(self) -> str:
        return self._quote_code

    async def snapshot(self, as_of: str) -> Snapshot:
        """The book both ways, the balances, and a reference price if there is one."""
        asks = await self._offers(gets=self._native(), pays=self._issued())
        bids = await self._offers(gets=self._issued(), pays=self._native())
        balances = await self._balances()
        return Snapshot(
            as_of=as_of,
            base=self._base,
            quote=self._quote_code,
            balances=balances,
            book=Book(
                best_bid=_best(bids, side="bid"),
                best_ask=_best(asks, side="ask"),
                mid=_mid(_best(bids, side="bid"), _best(asks, side="ask")),
                spread=_spread(_best(bids, side="bid"), _best(asks, side="ask")),
                buy_depth=tuple(_walk(asks, size, side="ask") for size in self._depths),
                sell_depth=tuple(_walk(bids, size, side="bid") for size in self._depths),
            ),
            reference=await self.reference(),
        )

    async def reference(self) -> Reference:
        """One external price. Allowed to be missing; never allowed to be a float."""
        try:
            response = await self._client.get(self._reference_url)
            response.raise_for_status()
            document = json.loads(response.text, parse_float=Decimal)
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            return Reference(source=self._reference_source, price=None, error=str(exc)[:200])
        found: Any = document
        for step in self._reference_path:
            if not isinstance(found, dict) or step not in found:
                return Reference(
                    source=self._reference_source,
                    price=None,
                    error=f"no {'.'.join(self._reference_path)} in the response",
                )
            found = found[step]
        try:
            price = Decimal(found) if isinstance(found, str | int | Decimal) else None
        except InvalidOperation:
            price = None
        if price is None or price <= 0:
            return Reference(
                source=self._reference_source,
                price=None,
                error=f"{'.'.join(self._reference_path)} is not a positive number",
            )
        return Reference(source=self._reference_source, price=price)

    # -- JSON-RPC ---------------------------------------------------------- #

    def _native(self) -> JSONObject:
        return {"currency": XRP}

    def _issued(self) -> JSONObject:
        return {"currency": currency_code(self._quote_code), "issuer": self._quote_issuer}

    async def _call(self, method: str, params: JSONObject) -> dict[str, Any]:
        try:
            response = await self._client.post(
                self._url, json={"method": method, "params": [params]}
            )
            response.raise_for_status()
            body = json.loads(response.text, parse_float=Decimal)
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            raise MarketError(f"{method} against {self._url} failed: {exc}") from exc
        result = body.get("result") if isinstance(body, dict) else None
        if not isinstance(result, dict):
            raise MarketError(f"{method} returned no result object")
        status = result.get("status")
        if status == "error":
            raise MarketError(f"{method}: {result.get('error_message') or result.get('error')}")
        return result

    async def _offers(self, *, gets: JSONObject, pays: JSONObject) -> list[dict[str, Any]]:
        result = await self._call(
            "book_offers", {"taker_gets": gets, "taker_pays": pays, "limit": BOOK_LIMIT}
        )
        offers = result.get("offers")
        if not isinstance(offers, list):
            return []
        return [entry for entry in offers if isinstance(entry, dict)]

    async def _balances(self) -> dict[str, Decimal]:
        info = await self._call(
            "account_info", {"account": self._treasury, "ledger_index": "validated"}
        )
        data = info.get("account_data")
        drops = data.get("Balance") if isinstance(data, dict) else None
        balances = {self._base: _drops(drops)}
        lines = await self._call(
            "account_lines", {"account": self._treasury, "ledger_index": "validated"}
        )
        rows = lines.get("lines")
        target = currency_code(self._quote_code)
        held = Decimal(0)
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            if currency_code(str(row.get("currency", ""))) != target:
                continue
            if str(row.get("account", "")) != self._quote_issuer:
                continue
            held += _number(row.get("balance"))
        balances[self._quote_code] = held
        return balances


# -- book arithmetic -------------------------------------------------------- #


def _walk(offers: Sequence[dict[str, Any]], size: Decimal, *, side: str) -> Level:
    """Fill ``size`` of the base asset against the book and report what it cost.

    ``side="ask"`` walks offers that *give* the base asset, so filling means
    buying it; ``side="bid"`` walks offers that *take* it, so filling means
    selling. Either way the answer is quote-per-base over the part that filled,
    and a book too thin to fill the size says so rather than extrapolating.
    """
    remaining, base_filled, quote_moved = size, Decimal(0), Decimal(0)
    for offer in offers:
        base, quote = _sides(offer, side=side)
        if base <= 0 or quote <= 0:
            continue
        take = min(remaining, base)
        base_filled += take
        quote_moved += take * quote / base
        remaining -= take
        if remaining <= 0:
            break
    price = (quote_moved / base_filled) if base_filled > 0 else None
    return Level(size=size, filled=base_filled, price=_round(price))


def _sides(offer: dict[str, Any], *, side: str) -> tuple[Decimal, Decimal]:
    """``(base, quote)`` for one offer, in the asset's own units."""
    gets, pays = offer.get("TakerGets"), offer.get("TakerPays")
    if side == "ask":  # the maker gives XRP and takes the issued asset
        return _amount(gets), _amount(pays)
    return _amount(pays), _amount(gets)


def _best(offers: Sequence[dict[str, Any]], *, side: str) -> Decimal | None:
    for offer in offers:
        base, quote = _sides(offer, side=side)
        if base > 0 and quote > 0:
            return _round(quote / base)
    return None


def _mid(bid: Decimal | None, ask: Decimal | None) -> Decimal | None:
    return None if bid is None or ask is None else _round((bid + ask) / 2)


def _spread(bid: Decimal | None, ask: Decimal | None) -> Decimal | None:
    return None if bid is None or ask is None else _round(ask - bid)


def _amount(value: Any) -> Decimal:
    """An XRPL amount: drops as a bare string, or an issued object with ``value``."""
    if isinstance(value, dict):
        return _number(value.get("value"))
    return _drops(value)


def _drops(value: Any) -> Decimal:
    return _number(value) / DROPS_PER_XRP


def _number(value: Any) -> Decimal:
    if isinstance(value, Decimal):
        return value
    if isinstance(value, bool) or value is None:
        return Decimal(0)
    try:
        return Decimal(str(value))
    except InvalidOperation:
        return Decimal(0)


def _round(value: Decimal | None) -> Decimal | None:
    """Six places, and never a negative zero. Display only — intents carry more."""
    if value is None:
        return None
    return value.quantize(PRICE_PLACES) + Decimal(0)


def _opt(value: Decimal | None) -> str | None:
    return None if value is None else format_decimal(value)


__all__ = [
    "Book",
    "Level",
    "MarketError",
    "MarketReader",
    "Reference",
    "Snapshot",
]
