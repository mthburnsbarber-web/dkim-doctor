#!/usr/bin/env node
// dkim-doctor — one-shot SPF / DKIM / DMARC health check for your sending domains.
//
//   dkim-doctor example.com other.com
//   dkim-doctor example.com --selectors s1,s2,mail
//
// The trap this tool exists for: your DKIM selector is probably not `default`.
// Providers publish under their own selector names, and a domain can pass every
// "is there a DKIM record?" check you wrote while real mail goes out unsigned —
// because you probed the wrong selector. The ground truth is the `header.s=`
// value in the Authentication-Results header of a real received message; this
// tool probes the common provider selectors and tells you what it finds.
//
// Exit codes: 0 all domains healthy, 1 problems found, 2 usage error.

import { promises as dns } from "node:dns";

const COMMON_SELECTORS = [
  "default", "mail", "smtp", "dkim", "k1", "k2", "k3", "s1", "s2", "s3",
  "selector1", "selector2", "google", "zoho", "pm", "fm1", "fm2", "fm3",
  "privateemail", "protonmail", "mandrill", "mailjet", "sendgrid", "smtpapi",
  "amazonses", "everlytickey1", "mxvault", "dk",
];

const args = process.argv.slice(2);
const domains = [];
let selectors = COMMON_SELECTORS;
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--selectors") selectors = String(args[++i]).split(",").map(s => s.trim()).filter(Boolean);
  else if (args[i].startsWith("--")) { console.error(`unknown flag ${args[i]}`); process.exit(2); }
  else domains.push(args[i]);
}
if (domains.length === 0) {
  console.error("usage: dkim-doctor <domain> [domain ...] [--selectors a,b,c]");
  process.exit(2);
}

const txt = async (name) => {
  try { return (await dns.resolveTxt(name)).map(parts => parts.join("")); }
  catch { return []; }
};

function rsaBits(p) {
  // Rough RSA key size from the base64 public key length.
  const bytes = Math.floor((p.length * 3) / 4);
  if (bytes > 400) return 4096;
  if (bytes > 200) return 2048;
  if (bytes > 100) return 1024;
  return null;
}

let problems = 0;
const warn = (msg) => { problems++; console.log(`  ✗ ${msg}`); };
const ok = (msg) => console.log(`  ✓ ${msg}`);

for (const domain of domains) {
  console.log(`\n${domain}`);

  // --- SPF ---
  const spf = (await txt(domain)).filter(r => r.toLowerCase().startsWith("v=spf1"));
  if (spf.length === 0) warn("SPF: no v=spf1 record");
  else if (spf.length > 1) warn(`SPF: ${spf.length} v=spf1 records — receivers treat multiple records as PermError`);
  else {
    const r = spf[0];
    if (/\s\+all\b/.test(r)) warn(`SPF: +all lets anyone send as you — ${r}`);
    else if (/\s\?all\b/.test(r)) warn(`SPF: ?all is neutral (no protection) — ${r}`);
    else ok(`SPF: ${r}`);
    const lookups = (r.match(/\b(include:|a[\s:]|mx\b|ptr\b|exists:|redirect=)/g) || []).length;
    if (lookups > 10) warn(`SPF: ~${lookups} DNS-lookup mechanisms (limit is 10 → PermError)`);
  }

  // --- DMARC ---
  const dmarc = (await txt(`_dmarc.${domain}`)).filter(r => r.toLowerCase().startsWith("v=dmarc1"));
  if (dmarc.length === 0) warn("DMARC: no record at _dmarc — mailbox providers increasingly require one");
  else {
    const policy = (dmarc[0].match(/\bp=([a-z]+)/i) || [])[1] || "?";
    if (policy === "none") console.log(`  ~ DMARC: p=none (monitoring only) — ${dmarc[0]}`);
    else ok(`DMARC: p=${policy}`);
  }

  // --- DKIM ---
  const found = [];
  await Promise.all(selectors.map(async (sel) => {
    const records = await txt(`${sel}._domainkey.${domain}`);
    const rec = records.find(r => /(^|;)\s*p=/.test(r));
    if (rec) {
      const p = (rec.match(/p=([^;\s]+)/) || [])[1] || "";
      if (!p) found.push({ sel, note: "REVOKED (empty p=)" });
      else found.push({ sel, note: `${rsaBits(p) ?? "?"}-bit key` });
    }
  }));
  if (found.length === 0) {
    warn(`DKIM: no key under ${selectors.length} probed selectors`);
    console.log("    → ground truth: send yourself a message and read header.s= in Authentication-Results");
  } else {
    for (const f of found) {
      if (f.note.startsWith("REVOKED")) warn(`DKIM: selector "${f.sel}" is ${f.note}`);
      else {
        ok(`DKIM: selector "${f.sel}" — ${f.note}`);
        if (f.note.startsWith("1024")) warn(`DKIM: "${f.sel}" key is 1024-bit — rotate to 2048`);
      }
    }
  }
}

console.log(`\n${problems === 0 ? "HEALTHY" : problems + " problem(s) found"} across ${domains.length} domain(s)`);
process.exit(problems === 0 ? 0 : 1);
