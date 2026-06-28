// Quick manual test of the passive checks (no Anthropic key needed).
import {
  normalizeDomain,
  isValidDomain,
  checkDns,
  checkSsl,
  checkSubdomains,
  checkHeaders,
  inferProvider,
  withTimeout,
} from "../netlify/functions/lib/checks.js";
import { deriveFindings, fallbackClassify } from "../netlify/functions/lib/findings.js";

const domain = normalizeDomain(process.argv[2] || "github.com");
console.log("Testing domain:", domain, "valid:", isValidDomain(domain));

const [dns, ssl, subs, hdrs] = await Promise.all([
  withTimeout(checkDns(domain), 6000, { error: "timeout" }),
  withTimeout(checkSsl(domain), 8000, { error: "timeout" }),
  withTimeout(checkSubdomains(domain), 8000, { subdomains: [], error: "timeout" }),
  withTimeout(checkHeaders(domain), 8000, { error: "timeout" }),
]);

console.log("\nDNS:", JSON.stringify(dns, null, 2));
console.log("\nSSL:", JSON.stringify(ssl, null, 2));
console.log("\nSubdomains:", subs.subdomains?.length, "found. Sample:", (subs.subdomains || []).slice(0, 10));
console.log("\nHeaders:", JSON.stringify(hdrs, null, 2));
console.log("\nProvider:", inferProvider(dns.nameservers || []));

const scan = {
  domain,
  dns: { spf: dns.spf, dmarc: dns.dmarc, mx: dns.mx },
  ssl,
  subdomains: subs.subdomains || [],
  headers: hdrs,
  nameservers: dns.nameservers || [],
};
const { findings, provider } = deriveFindings(scan);
console.log("\nDerived findings:", findings.length, "provider:", provider);
for (const f of findings) {
  const fb = fallbackClassify(f);
  console.log(` - [${fb.severity}] ${f.label}`);
}
