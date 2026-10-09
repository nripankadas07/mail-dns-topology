# Runnable example

Run `python demo.py`; it exercises the exact source API and fails if the intended positive/negative result changes. The installed CLI is separately exercised by `python verify.py` from outside the source directory.

Commands in `smoke.json` document the expected exit status for good, findings/replay and malformed-input cases. Snapshot files are synthetic and intentionally contain no credentials or private production data.

Reconstruct TXT records per resource record, traverse reachable include/redirect edges, identify cycles/missing or multiple SPF records, check declared DMARC policy, DKIM selector presence and captured MX addresses.

No DNS queries or TTL/freshness claim. Only TXT, MX, A and AAAA snapshot records. SPF supports include, redirect, literal ip4/ip6 and all; other terms/macros produce explicit findings. Not SPF source-IP authentication, full RFC syntax validation, DNS lookup-budget calculation or deliverability certification. DKIM p is checked for presence/nonempty only, not cryptographic validity; no CNAME/null MX/organizational DMARC fallback. DMARC validates only explicit v/p tags. Captured data can be stale or incomplete. 2 MiB CLI limit, 10,000 records, 100 selectors.
