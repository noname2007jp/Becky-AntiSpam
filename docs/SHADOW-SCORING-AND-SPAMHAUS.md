# Shadow Scoring and Spamhaus DNSBL Integration Plan

Updated: 2026-11-20

## Goals

1. Evaluate correlation-adjusted Bayes on normal incoming business mail without repeatedly labeling near-duplicate messages.
2. Keep the production verdict unchanged until shadow results demonstrate acceptable false-positive behavior.
3. Add Spamhaus reputation as an independent signal, not as an unconditional block rule.
4. Keep the Becky! receive/filter callback fast and deterministic; network lookups must never block it.

## Phase A: Correlation-adjusted Bayes shadow scoring

- Reuse the already implemented `BayesComparison::correlation_adjusted_probability` and `correlation_adjusted_evidence_log_odds`.
- Add a separately named candidate score/verdict to diagnostic output and evaluation storage. Do not overload the existing Symbol v1/v2 fields.
- Compute the candidate on the same parsed message and same model snapshot as the active classifier.
- Do not feed candidate results into the active verdict, training decision, or mail movement.
- Record only aggregate score/verdict and existing anonymous evaluation case number. Never record body, sender, subject, URLs, token strings, message IDs, or raw domains.
- Use a bounded evidence contribution and explicit threshold configuration. Do not choose a production threshold from the current 54 Spam-labeled sample alone.
- Compare against the active verdict on naturally arriving mail. Avoid asking the user to repeatedly label similar business templates. Ask for labels only when a genuinely new/uncertain case occurs or when the user naturally handles a message.

Acceptance:
- Active verdict is byte-for-byte behaviorally unchanged with shadow mode on/off.
- Unit tests prove candidate calculation cannot alter the active verdict or training counts.
- Evaluation output reports candidate confusion matrix separately.
- Windows x86 CI passes.

## Phase B: Spamhaus integration design

### Data sources

- ZEN: IP reputation (combined SBL/XBL/PBL). Query only a carefully selected public sending IP, not every IP found in Received headers.
- DBL: domain reputation. Query a small, bounded set of extracted domains (e.g. sender domain and URL hostnames); DBL is domain-only.
- Do not query PBL against URL hosts or arbitrary Received-chain IPs. PBL is intended for SMTP connection-source policy checks and can flag legitimate end-user IPs.
- Do not separately query SBL/XBL/PBL when using ZEN unless a documented requirement needs component return-code interpretation.

### Licensing and account requirements

- Do not hard-code or distribute a shared Spamhaus key.
- Before enabling lookups, the operator must obtain their own access credentials and confirm that their intended business use and deployment model are permitted by Spamhaus terms.
- Public mirrors are limited to eligible non-commercial, low-volume use and have resolver/network attribution requirements.
- The free Blocklists via DNS Query account is also limited to eligible non-commercial small organizations/individuals, with a stated sustained query-volume ceiling. Commercial organizations, ISPs, and commercial filtering services require a commercial subscription.
- Do not proxy a single user's key for third-party users or bundle the data/service into a distributed product.
- DNS lookup errors, blocked queries, malformed responses, and timeouts must be treated as UNKNOWN, never as a listing.

### Runtime architecture

- No DNS/network operation in Becky! receive/filter callback.
- A background worker performs bounded DNSBL lookups; results are cached by normalized query key with TTL and a maximum cache size.
- The classifier consumes only previously cached results. A cache miss is UNKNOWN and has no negative score.
- Set strict limits: small number of IP/domain candidates per message, short timeout, bounded queue, duplicate suppression, and no retry storm.
- Keep the lookup feature disabled by default until credentials and usage terms are confirmed.
- Provide explicit settings for enable/disable and diagnostics. Never log the raw message, sender, subject, queried domain, or full IP. Aggregate counts and status only.
- Initial integration is shadow-only: report DNSBL status and a candidate contribution without changing Ham/Review/Spam.
- Only consider a conservative positive contribution for a valid listed response. Never treat DNS errors or query-limit return codes as listed.
- Do not make a direct Spam verdict from DBL or ZEN alone in the first release.

### Candidate extraction and safety

- Parse the trusted/most likely originating public IP using a documented Received-chain strategy; Received headers are untrusted and can be forged. If origin cannot be determined confidently, skip ZEN.
- Exclude private, loopback, link-local, reserved, and documentation IP ranges.
- Normalize domains to lowercase IDNA ASCII, strip trailing dot, reject IP literals for DBL, and avoid querying common provider domains as a blanket sender-only rule.
- For URLs, query registrable domains only after safe hostname parsing; cap the number of domains.
- Do not inspect or transmit full URLs, paths, query strings, message text, or attachments.

Acceptance:
- DNS tests cover listed, not-listed, timeout, NXDOMAIN, malformed response, and Spamhaus error return codes.
- Parser tests cover spoofed/multiple Received headers, private IPs, IDN domains, URL host extraction, and candidate caps.
- DNS outage does not delay mail filtering or alter the active verdict.
- Lookup count, queue depth, cache hit rate, and aggregate result counts are logged without personal/message data.

## Phase C: Staged rollout

1. Merge only after CI and source review; keep PR #2 unmerged until its current changes are independently reviewed.
2. Implement and validate Bayes shadow candidate first.
3. Implement Spamhaus DNSBL behind a separate disabled-by-default feature flag.
4. Run both in shadow mode during ordinary mail use; do not require a large repeated-label exercise.
5. Review a small number of genuinely novel false-positive/false-negative cases.
6. Decide whether to activate each signal independently. Keep a rollback switch and preserve the active classifier as fallback.

## Explicit non-goals

- No automatic mail deletion or movement.
- No production verdict change in the shadow phase.
- No embedding of a shared Spamhaus credential.
- No full message upload to an external reputation service.
- No use of Spamhaus data to train an AI model.
