# DNS Sending Checklist

Use this when setting up or auditing a domain that sends mail.

## SPF

- Publish exactly one TXT record at the root domain that starts with `v=spf1`.
- Use `-all` once every legitimate sender is included.
- Avoid `+all` and `?all`.
- Count DNS lookup mechanisms: `include:`, `a`, `mx`, `ptr`, `exists:`, and
  `redirect=`. Receivers can fail SPF after 10 lookups.

## DKIM

- Find the selector from a real received message:
  `Authentication-Results` -> `header.s=selector`.
- Check the selector published at `selector._domainkey.example.com`.
- Rotate 1024-bit keys to 2048-bit or stronger where the provider supports it.
- Remove revoked empty `p=` records after the sending provider no longer needs
  them.

## DMARC

- Publish a TXT record at `_dmarc.example.com`.
- Start with `p=none` only while collecting reports.
- Move to `quarantine` or `reject` after legitimate senders pass SPF or DKIM
  alignment.
- Use a monitored `rua=` mailbox or reporting service.

## Run

```bash
node dkim-doctor.mjs example.com
```

Healthy output does not prove inbox placement. It proves the DNS authentication
surface is present enough to support delivery.
