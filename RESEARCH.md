# Brief and comparable review — 9 October 2026

Observation: 9 October 2026, 06:34 UTC. Live connected GitHub queries `spf dmarc validation sort:stars; dmarc in:name sort:stars; mail authentication sort:stars; checkdmarc in:name sort:stars` sorted by stars, bounded result pages. Repository star counts fetched separately, with current default-branch code/docs/issues. Highest-star relevant comparable found: **domainaware/parsedmarc (1,304), a related report tool; highest direct DNS validator found is checkdmarc (321)**. This is not an exhaustive global ranking; HTML-only parsers, unrelated extractors, mobile-only release automation and report-only tools were distinguished by workflow relevance. Stars are discovery signals, not reliability/performance measurements.

Actual user: Mail platform engineers reviewing a captured proposed DNS change before publishing it.

Painful task: SPF include/redirect dependencies span names, TXT fragments are easy to mishandle, and a missing captured target makes a change review ambiguous.

Smallest useful capability: Reconstruct TXT records per resource record, traverse reachable include/redirect edges, identify cycles/missing or multiple SPF records, check declared DMARC policy, DKIM selector presence and captured MX addresses.

Acceptance: good synthetic fixture passes; confirmed contract violation produces actionable JSON/exit 1; malformed input produces exit 2; installed quickstart works outside source; core boundary/concurrency/format regressions pass; remote Python matrix passes before LIVE.

Evidence and demand: Verified general issue evidence: [checkdmarc #286](https://github.com/domainaware/checkdmarc/issues/286), opened 25 September 2026, reports version-prefix TXT fragment handling across include/redirect targets. We read the report and current source, but did not reproduce the competitor comparison. This MVP tests joining chunks within one record without joining separate records. Need for this exact MVP is inferred, not an upstream request to build it.

Portfolio/distinctness: dnswarden covers DNS blocklists; this is a captured mail-configuration dependency graph and selector contract. It neither resolves DNS nor filters hosts. Compared all five briefs and 148 current owned repository descriptions and files where overlapping. No fork, rename or product subdivision counted as new.

Discovery: Mail DNS change-review examples, SPF topology searches and DNS-validation topics.

| Comparable | Stars | Last push UTC | License metadata | Observed workflow/capability tradeoff |
| --- | ---: | --- | --- | --- |
| [domainaware/checkdmarc](https://github.com/domainaware/checkdmarc) | 321 | 2026-09-21T00:24:19Z | Apache-2.0 | pip-installable live DNS validator with SPF lookup handling, DNSSEC and DMARC/BIMI; broader protocol analysis. |
| [domainaware/parsedmarc](https://github.com/domainaware/parsedmarc) | 1304 | 2026-10-05T14:41:56Z | Apache-2.0 | DMARC report parsing and analysis with integration destinations; different report-analysis workflow. |
| [postalsys/mailauth](https://github.com/postalsys/mailauth) | 147 | 2026-10-04T17:04:17Z | NOASSERTION | Node mail authentication covering SPF/DKIM/DMARC/ARC with lookup options; broader message authentication. |

- [domainaware/checkdmarc source](https://github.com/domainaware/checkdmarc/blob/22e06b08f41658962167e12aca2c141ae338fbb5/checkdmarc/spf.py), head `22e06b08f41658962167e12aca2c141ae338fbb5`. README `README.md`, source and up to five current issue/PR entries read. Maintenance signal is the dated push, not a guarantee of support. Issue examples: Migration from httpx to httpx2?, Fix SPF selection across TXT string boundaries
- [domainaware/parsedmarc source](https://github.com/domainaware/parsedmarc/blob/af63675aeb494636d1f1d6071e7f13ecfafefe6e/parsedmarc/__init__.py), head `af63675aeb494636d1f1d6071e7f13ecfafefe6e`. README `README.md`, source and up to five current issue/PR entries read. Maintenance signal is the dated push, not a guarantee of support. Issue examples: Store reports in Elasticsearch/OpenSearch data streams instead of dated indexes, Add Google SecOps (Chronicle) support: events.import output and UDM parser
- [postalsys/mailauth source](https://github.com/postalsys/mailauth/blob/9faa0fcbeb6a70b4e77e96701e89d7b7ffcf9658/lib/commands/spf.js), head `9faa0fcbeb6a70b4e77e96701e89d7b7ffcf9658`. README `README.md`, source and up to five current issue/PR entries read. Maintenance signal is the dated push, not a guarantee of support. Issue examples: 

Installability, time to first result, reliability and support comparison: README instructions, examples, current source and issues were reviewed. Competitor clean installations, workload timing, historical support response and demo reliability were **not measured**. Our own clean installation/demo proves only our behavior. NOASSERTION is incomplete license metadata, not a conclusion about permission. Licenses/attribution require actual upstream license review before reuse; no upstream code reused here.

No technical-performance benchmark or superiority claim. Workloads/hardware/versions were not measured equivalently, so stars and a successful example do not imply we outperform these tools. Broader tools already offer valuable workflows; this MVP chooses a small explicit contract with significant limits.
