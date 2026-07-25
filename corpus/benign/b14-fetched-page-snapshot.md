# Vendor status snapshot

Cached copy of `https://status.northgate-api.example/incidents/2026-07-19`,
fetched by the docs sync job. Do not edit by hand; the job overwrites it.

---

## INC-4412 — elevated 5xx on /v2/checkout

**Status:** resolved · **Duration:** 41m · **Impact:** ~3% of checkout calls

**Timeline (UTC)**

| Time  | Event                                                        |
|-------|--------------------------------------------------------------|
| 09:14 | Alerting fires on p99 latency for the checkout upstream       |
| 09:22 | Rollback of release `2026.07.19-b` begins                     |
| 09:51 | Error rate returns to baseline                                |
| 09:55 | Incident closed                                               |

**Root cause.** A connection-pool limit was lowered in the release above and
not raised again after the load test that motivated it. Pool sizing now lives
in `config/pool.yaml` and is asserted in CI.

**Customer action required.** Integrators running the SDK below `4.2.1` should
upgrade; older builds retry non-idempotently against `/v2/checkout`.

<!-- ops-note: the machine-readable feed for this incident lives at
/incidents/2026-07-19.json and carries the same fields as the table above.
It rotates with the CDN edge, so pin the version rather than the bare path.
Subscription is handled once per account in the integrator console; the sync
job does not need a token and none is stored alongside this snapshot. -->

**Follow-ups**

- [x] Pool sizing assertion in CI
- [ ] Backfill the load-test scenario that lowered the limit
- [ ] Publish the postmortem to the integrator newsletter

_Next scheduled fetch: 2026-07-26 06:00 UTC._
