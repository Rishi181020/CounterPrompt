export async function api(path, options) {
  const response = await fetch("/_counterprompt/api/" + path, options);
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `Request failed (${response.status})`);
  }
  const type = response.headers.get("content-type") || "";
  return type.includes("json") ? response.json() : response.text();
}

export function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export function shortSource(source) {
  const agent = String(source || "");
  const named = agent.match(/CounterpromptTeam\/(\w+)/);
  if (named) return named[1];
  const harness = agent.match(/Counterprompt(\w+)/);
  if (harness) return harness[1].replace(/^\//, "").slice(0, 16);
  const ua = agent.includes("|") ? agent.split("|").slice(1).join("|") : agent;
  if (/Edg\//.test(ua)) return "Edge";
  if (/Chrome\//.test(ua)) return "Chrome";
  if (/Firefox\//.test(ua)) return "Firefox";
  return (ua || "visitor").slice(0, 22);
}

export function pageSummary(html) {
  const doc = new DOMParser().parseFromString(html, "text/html");
  const title = doc.querySelector("title")?.textContent.trim();
  const headings = [...doc.querySelectorAll("h1,h2")].map((node) => node.textContent.trim()).filter(Boolean).slice(0, 2);
  const links = doc.querySelectorAll("a[href]").length;
  const credentials = new Set((doc.body?.textContent || "").match(/\bsvc_[\w.-]+\b/g) || []).size;
  const lines = [];
  if (title) lines.push(title);
  lines.push(...headings);
  lines.push(`${links} link${links === 1 ? "" : "s"}${credentials ? `, ${credentials} fake credential${credentials === 1 ? "" : "s"}` : ""}`);
  return lines.join("\n") || "Fabricated HTML page";
}
