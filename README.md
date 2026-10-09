# mail-dns-topology

Offline mail-DNS snapshot topology: SPF edges, cycles, TXT fragments, DKIM selectors and MX addresses.

## Who and why

Mail platform engineers reviewing a captured proposed DNS change before publishing it. SPF include/redirect dependencies span names, TXT fragments are easy to mishandle, and a missing captured target makes a change review ambiguous.

Reconstruct TXT records per resource record, traverse reachable include/redirect edges, identify cycles/missing or multiple SPF records, check declared DMARC policy, DKIM selector presence and captured MX addresses.

## Quickstart

Python 3.10+ and pip. Git source installation, no external-registry publication:

```sh
git clone https://github.com/nripankadas07/mail-dns-topology.git
cd mail-dns-topology
python -m venv .venv
# Unix: source .venv/bin/activate; Windows: .venv\Scripts\activate
python -m pip install .
mail-dns-topology snapshot.json
python demo.py
python verify.py
```

CLI JSON on stdout. Exit **0** passes/claims, **1** policy findings or authentication/replay rejection, **2** malformed/unsupported input or IO errors. For automation, inspect the JSON and exit status together. Help: `mail-dns-topology --help`.

The fixture data is entirely synthetic. `demo.py` runs the example without installation and asserts a useful success and failure. `verify.py` additionally checks source tests, compilation and a fresh wheel installation in a temporary environment outside the source directory.

## Input and output

Read the checked-in fixture and policy JSON alongside `mail_dns_topology.py`. Policies reject unknown keys and invalid types rather than silently defaulting. See [DEMO.md](DEMO.md) for exact commands, expected outcome and schema notes; [VALIDATION.md](VALIDATION.md) for measured checks; [RESEARCH.md](RESEARCH.md) for dated comparable evidence and limits.

## Scope and limits

No DNS queries or TTL/freshness claim. Only TXT, MX, A and AAAA snapshot records. SPF supports include, redirect, literal ip4/ip6 and all; other terms/macros produce explicit findings. Not SPF source-IP authentication, full RFC syntax validation, DNS lookup-budget calculation or deliverability certification. DKIM p is checked for presence/nonempty only, not cryptographic validity; no CNAME/null MX/organizational DMARC fallback. DMARC validates only explicit v/p tags. Captured data can be stale or incomplete. 2 MiB CLI limit, 10,000 records, 100 selectors.

## Support

[Support, contribution and security](SUPPORT.md). MIT license. No performance or superiority claim; existing established tools are preferable when you need their broader workflows.
