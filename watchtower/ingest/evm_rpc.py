"""Read-only Base/EVM JSON-RPC client.

Same shape and same guarantees as solana_rpc.SolanaRPC, kept as a separate
class rather than generalised into one: the two chains share a transport
(JSON-RPC over HTTP) and nothing else. Method names, parameter encoding, error
codes, pagination, and rate-limit behaviour all differ, and a single "universal
RPC client" would be a pile of `if chain ==` branches that is harder to audit
than two small honest clients.

READ_ONLY_METHODS is the load-bearing detail. `eth_sendRawTransaction` is not in
the set and cannot be reached through `call()`, so the read-only promise is
enforced by construction rather than by reviewer discipline. The watchtower
never signs, never sends, never dusts a wallet, and never writes a memo --
sending unsolicited memos would be address poisoning, the exact pattern this
tool exists to scan for.

Honest limitation on the public endpoint: Base publishes no documented rate
limits for mainnet.base.org and its own docs say it is not for production
workloads. We therefore default to a conservative 3 rps and treat any 429 as
authoritative, halving our own rate rather than assuming a published budget
that does not exist.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import requests

from .base import RpcError  # shared base class: one `except RpcError` catches both chains

PUBLIC_BASE = "https://mainnet.base.org"

# Base documents no rate limit and warns the public endpoint is not for
# production. 3 rps is a guess made deliberately low; the adaptive backoff in
# `call()` is what actually keeps us polite.
DEFAULT_RPS = 3.0


@dataclass
class RpcStats:
    """Every number a report cites about ingestion cost comes from here."""

    calls: int = 0
    errors: int = 0
    retries: int = 0
    rate_limited: int = 0
    by_method: dict = field(default_factory=dict)

    def note(self, method: str) -> None:
        self.calls += 1
        self.by_method[method] = self.by_method.get(method, 0) + 1


class EvmRPC:
    """Minimal, polite, read-only JSON-RPC client for Base.

    Structured so an Alchemy/QuickNode/Helius endpoint slots in by changing
    `url` and raising `rps`; no other code changes.
    """

    READ_ONLY_METHODS = {
        "eth_blockNumber",
        "eth_getBlockByNumber",
        "eth_getTransactionByHash",
        "eth_getTransactionReceipt",
        "eth_getCode",
        "eth_getLogs",
        "eth_chainId",
    }

    def __init__(
        self,
        url: str = PUBLIC_BASE,
        rps: float = DEFAULT_RPS,
        timeout: int = 45,
        max_retries: int = 5,
        stats: RpcStats | None = None,
    ) -> None:
        self.url = url
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self.timeout = timeout
        self.max_retries = max_retries
        self.stats = stats or RpcStats()
        self._session = requests.Session()
        self._last_call = 0.0
        self._id = 0

    def _throttle(self) -> None:
        gap = time.monotonic() - self._last_call
        if gap < self.min_interval:
            time.sleep(self.min_interval - gap)
        self._last_call = time.monotonic()

    def call(self, method: str, params: list):
        if method not in self.READ_ONLY_METHODS:
            # Hard guard: read-only by construction. eth_sendRawTransaction can
            # never be reached from here.
            raise RpcError(f"method not allowed (read-only service): {method}")

        backoff = 1.0
        last_exc = None
        for _ in range(self.max_retries):
            self._throttle()
            self._id += 1
            try:
                resp = self._session.post(
                    self.url,
                    json={
                        "jsonrpc": "2.0",
                        "id": self._id,
                        "method": method,
                        "params": params,
                    },
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                last_exc = exc
                self.stats.retries += 1
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue

            self.stats.note(method)

            if resp.status_code in (429, 503):
                self.stats.rate_limited += 1
                self.stats.retries += 1
                retry_after = resp.headers.get("retry-after")
                sleep_for = float(retry_after) if retry_after else backoff
                time.sleep(min(sleep_for, 60))
                backoff = min(backoff * 2, 30)
                continue

            if resp.status_code != 200:
                last_exc = RpcError(f"HTTP {resp.status_code}: {resp.text[:200]}")
                self.stats.retries += 1
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue

            body = resp.json()
            if "error" in body:
                err = body["error"]
                # Permanent client errors: do not burn retries on them.
                if err.get("code") in (-32602, -32601):
                    self.stats.errors += 1
                    raise RpcError(f"{method}: {err}")
                last_exc = RpcError(f"{method}: {err}")
                self.stats.retries += 1
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue

            return body.get("result")

        self.stats.errors += 1
        raise RpcError(f"{method} failed after {self.max_retries} attempts: {last_exc}")

    def block_number(self) -> int:
        return int(self.call("eth_blockNumber", []), 16)

    def block_by_number(self, number: int, full: bool = True) -> dict | None:
        return self.call("eth_getBlockByNumber", [hex(number), full])

    def get_code(self, address: str) -> str:
        return self.call("eth_getCode", [address, "latest"]) or "0x"

    def get_logs(self, params: dict) -> list:
        return self.call("eth_getLogs", [params]) or []
