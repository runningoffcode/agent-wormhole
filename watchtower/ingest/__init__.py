"""Pluggable, read-only ingestion sources for the Chain Watchtower.

Everything in this package produces the same thing: transaction dicts in the
shape `wormhole/scanners/memos.py` already parses, plus a cursor saying where
it stopped. Downstream code never learns which endpoint the data came from,
which is what makes a future Helius/Yellowstone migration a new class in here
and zero changes anywhere else.

Boundary rule, enforced by a test: watchtower imports from wormhole/, never the
reverse. The free local package stays offline and dependency-free.

`build_source` is a deliberately small registry. Imports are done lazily inside
it so that using the replay source -- the only one that needs no network --
does not require `requests` to be installed at all.
"""

from __future__ import annotations

from .base import (  # noqa: F401
    STOP_ERROR,
    STOP_EXHAUSTED,
    STOP_RATE_LIMITED,
    STOP_TARGET,
    Batch,
    Cursor,
    CursorStore,
    RateLimiter,
    Source,
)

# Name -> one-line description, used by the CLI's --list-sources.
SOURCES = {
    "solana-index": "Solana memo programs via getSignaturesForAddress (wide, ~1 call/1000 sigs)",
    "solana-rpc": "Solana memo programs via full jsonParsed getTransaction (precise, ~1 call/tx)",
    "base-calldata": "Base EOA-destination calldata via eth_getBlockByNumber (forward-paging)",
    "replay": "A saved transaction dump on disk (no network; reproducible)",
}


def build_source(name: str, **kwargs) -> Source:
    """Construct a source by name. Imports lazily so replay needs no requests."""
    if name == "replay":
        from .replay import ReplaySource

        return ReplaySource(**kwargs)
    if name == "solana-index":
        from .solana import SolanaIndexSource

        return SolanaIndexSource(**kwargs)
    if name == "solana-rpc":
        from .solana import SolanaRpcSource

        return SolanaRpcSource(**kwargs)
    if name == "base-calldata":
        from .evm import BaseCalldataSource

        return BaseCalldataSource(**kwargs)
    raise ValueError(f"unknown source: {name!r} (known: {', '.join(sorted(SOURCES))})")


__all__ = [
    "Batch",
    "Cursor",
    "CursorStore",
    "RateLimiter",
    "SOURCES",
    "Source",
    "STOP_ERROR",
    "STOP_EXHAUSTED",
    "STOP_RATE_LIMITED",
    "STOP_TARGET",
    "build_source",
]
