# dkim-doctor

One-shot SPF / DKIM / DMARC health check for your sending domains.

```
$ node dkim-doctor.mjs example.com
example.com
  ✓ SPF: v=spf1 include:_spf.provider.net -all
  ~ DMARC: p=none (monitoring only) — v=DMARC1; p=none; rua=mailto:d@example.com
  ✓ DKIM: selector "s1" — 2048-bit key

HEALTHY across 1 domain(s)
```

## Why

Deliverability dies quietly. The specific trap this tool encodes: **your DKIM
selector is probably not `default`.** Providers publish keys under their own
selector names (`google`, `selector1`, `fm1`, `privateemail`, `k1`, …), and
each domain can differ. A naive check that only probes `default` will pass —
while your real mail goes out unsigned and lands in spam.

`dkim-doctor` probes ~28 common provider selectors per domain and also checks:

- **SPF** — record present, exactly one `v=spf1`, no `+all`/`?all`, and the
  10-DNS-lookup limit (exceeding it is a silent PermError).
- **DMARC** — record present; flags `p=none` as monitoring-only.
- **DKIM** — key found, revoked (empty `p=`) detection, and RSA key size
  (flags 1024-bit keys for rotation).

If nothing is found it tells you the real ground truth: send yourself a message
and read `header.s=` in the `Authentication-Results` header — that's the
selector your provider actually signs with.

## Usage

```
dkim-doctor <domain> [domain ...] [--selectors a,b,c]
```

Exit codes: `0` healthy, `1` problems, `2` usage error — cron it weekly and
alert on non-zero, because DNS changes, keys get revoked, and nobody notices
until reply rates crater.

Zero dependencies. Node 18+.

## License

MIT
