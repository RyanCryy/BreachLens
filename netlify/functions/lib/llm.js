// Thin wrapper around the OpenAI Chat Completions API using global fetch (Node 18+).
// No SDK dependency — keeps the function bundle tiny and deploys cleanly on Netlify.

const API_URL = "https://api.openai.com/v1/chat/completions";
const DEFAULT_MODEL = process.env.OPENAI_MODEL || "gpt-4o-mini";

export class LLMError extends Error {}

// Low-level call. Returns the assistant's text content.
// Pass jsonMode: true to request a strict JSON object response.
export async function callLLM({
  system,
  messages,
  maxTokens = 1024,
  temperature = 0,
  model = DEFAULT_MODEL,
  timeoutMs = 20000,
  jsonMode = false,
}) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) throw new LLMError("OPENAI_API_KEY is not configured");

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  // OpenAI puts the system prompt as the first message in the array.
  const fullMessages = [];
  if (system) fullMessages.push({ role: "system", content: system });
  for (const m of messages) fullMessages.push(m);

  const body = {
    model,
    max_tokens: maxTokens,
    temperature,
    messages: fullMessages,
  };
  if (jsonMode) body.response_format = { type: "json_object" };

  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      throw new LLMError(`OpenAI API ${res.status}: ${errText.slice(0, 300)}`);
    }

    const data = await res.json();
    const text = data?.choices?.[0]?.message?.content || "";
    return text;
  } finally {
    clearTimeout(timer);
  }
}

// Strip markdown fences / preamble and pull the first JSON object or array.
export function extractJson(raw) {
  if (!raw) throw new Error("Empty response");
  let s = raw.trim();

  // Remove ```json ... ``` fences if present
  const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) s = fence[1].trim();

  // Find the outermost JSON object/array
  const firstObj = s.indexOf("{");
  const firstArr = s.indexOf("[");
  let start = -1;
  if (firstObj === -1) start = firstArr;
  else if (firstArr === -1) start = firstObj;
  else start = Math.min(firstObj, firstArr);

  if (start === -1) return JSON.parse(s); // let it throw if truly invalid

  const openCh = s[start];
  const closeCh = openCh === "{" ? "}" : "]";
  const end = s.lastIndexOf(closeCh);
  if (end > start) s = s.slice(start, end + 1);

  return JSON.parse(s);
}

// Call the LLM expecting JSON. Retries once with a stricter instruction.
// Throws if both attempts fail to parse — caller decides on the fallback.
export async function callLLMJson(opts) {
  const { system, messages, ...rest } = opts;

  // Attempt 1 — JSON mode on
  try {
    const raw = await callLLM({ system, messages, jsonMode: true, ...rest });
    return extractJson(raw);
  } catch (err1) {
    // Attempt 2 — stricter instruction, JSON mode still on
    const stricterSystem =
      (system || "") +
      "\n\nCRITICAL: Return ONLY the raw JSON object, nothing else. No markdown, no code fences, no explanation, no leading or trailing text.";
    const raw2 = await callLLM({
      system: stricterSystem,
      messages,
      jsonMode: true,
      ...rest,
    });
    return extractJson(raw2); // if this throws, caller falls back
  }
}
