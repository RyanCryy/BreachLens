// Invoke the v2 scan function directly with a mock Request and stream the NDJSON.
import scan from "../netlify/functions/scan.js";

const domain = process.argv[2] || "github.com";
const req = new Request("https://local/api/scan", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ domain }),
});

console.log(`\n=== Scanning ${domain} (OPENAI_API_KEY ${process.env.OPENAI_API_KEY ? "set" : "NOT set → fallback expected"}) ===\n`);

const res = await scan(req);
console.log("HTTP", res.status, res.headers.get("content-type"));

const reader = res.body.getReader();
const dec = new TextDecoder();
let buf = "";
let result = null;
while (true) {
  const { value, done } = await reader.read();
  if (done) break;
  buf += dec.decode(value, { stream: true });
  let nl;
  while ((nl = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, nl).trim();
    buf = buf.slice(nl + 1);
    if (!line) continue;
    const evt = JSON.parse(line);
    if (evt.type === "result") {
      result = evt;
      console.log("event: result received");
    } else {
      console.log("event:", JSON.stringify(evt));
    }
  }
}

if (result) {
  console.log("\n--- REPORT ---");
  console.log("score:", result.report.overallRiskScore, "| level:", result.report.riskLevel, "| source:", result.report._source);
  console.log("summary:", result.report.summary);
  console.log("topPriority:", result.report.topPriority);
  console.log("findings:");
  for (const f of result.report.findings) {
    console.log(`  [${f.severity}] ${f.title}`);
    console.log(`     fix: ${f.recommendation}`);
  }
} else {
  console.log("No result payload (error path).");
}
