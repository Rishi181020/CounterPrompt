import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, formatTime, shortSource } from "../api";

const VECTORS = {
  direct: { label: "Chat message", banner: "Injection found in the chat message" },
  document: { label: "Attached doc", banner: "Embedded instruction found in attached document" },
  tool_result: { label: "Tool result", banner: "Embedded instruction found in tool result" },
};

function labelTurn(turn) {
  if (turn.shield === "blocked") {
    return { tone: "blocked", title: "Blocked at the gate", detail: turn.action || "Adversarial prompt never reached the support model." };
  }
  if (turn.shield === "redacted") {
    return { tone: "redacted", title: "Reply withheld", detail: turn.action || "The assistant tried to share restricted data; CounterPrompt redacted it." };
  }
  if (turn.shield === "contained") {
    return { tone: "contained", title: "Answered by Labyrinth", detail: turn.action || "This source was already contained; the real assistant never saw the message." };
  }
  if (turn.canary_leak) {
    return { tone: "leak", title: "Canary credential in reply", detail: turn.action || "Planted credential appeared in the model reply." };
  }
  if (turn.tool_misuse) {
    return { tone: "misuse", title: "Internal tool use", detail: turn.action || "The assistant called a tool against internal data." };
  }
  if (turn.injection) {
    return { tone: "injection", title: "Injection pattern", detail: turn.action || "Matched an adversarial pattern; delivered in observe mode." };
  }
  return { tone: "pass", title: "Delivered", detail: turn.action || "Normal support turn." };
}

function agentLabel(source, userAgent) {
  const raw = userAgent || (String(source || "").includes("|")
    ? String(source).split("|").slice(1).join("|")
    : source);
  const ua = String(raw || "");
  if (/SupportAgent/i.test(ua)) return "Support agent";
  if (/ExploreAgent/i.test(ua)) return "Crawl agent";
  if (/Verify\//i.test(ua)) return "Verify";
  if (/Harness/i.test(ua)) return "Harness";
  if (/Team\/(\w+)/.test(ua)) return `Team ${ua.match(/Team\/(\w+)/)[1]}`;
  if (/Mozilla/i.test(ua)) return "Browser (manual)";
  return shortSource(source || ua);
}

function initials(label) {
  const parts = String(label || "?").split(/\s+/).filter(Boolean);
  if (!parts.length) return "?";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[1][0]).toUpperCase();
}

function sparkTone(turn) {
  if (turn.shield === "blocked" || turn.canary_leak) return "blocked";
  if (turn.shield === "redacted" || turn.tool_misuse) return "redacted";
  if (turn.shield === "contained" || turn.injection) return "flagged";
  return "pass";
}

// Pull {"tool": ..., "args": {...}} objects out of the assistant text so they
// render as chips instead of raw JSON.
function splitReply(reply) {
  const text = String(reply || "");
  const calls = [];
  let out = "";
  let i = 0;
  while (i < text.length) {
    if (text[i] === "{") {
      let depth = 0;
      let inStr = false;
      let end = -1;
      for (let j = i; j < text.length; j += 1) {
        const ch = text[j];
        if (inStr) {
          if (ch === "\\") j += 1;
          else if (ch === '"') inStr = false;
        } else if (ch === '"') inStr = true;
        else if (ch === "{") depth += 1;
        else if (ch === "}") {
          depth -= 1;
          if (depth === 0) { end = j; break; }
        }
      }
      if (end > 0) {
        try {
          const obj = JSON.parse(text.slice(i, end + 1));
          if (obj && typeof obj === "object" && obj.tool) {
            calls.push({ name: String(obj.tool), args: obj.args || {} });
            i = end + 1;
            continue;
          }
        } catch {
          /* not JSON, keep as text */
        }
      }
    }
    out += text[i];
    i += 1;
  }
  return { text: out.replace(/```(json)?/g, "").trim(), calls };
}

function ToolChip({ tool }) {
  const args = tool.args && typeof tool.args === "object"
    ? Object.keys(tool.args).map((k) => `${k}=${JSON.stringify(tool.args[k])}`).join(", ")
    : "";
  return (
    <span className="support-chip mono" title={`${tool.name}(${args})`}>
      <b>⚙ {tool.name}</b>{args ? <span>{args}</span> : null}
    </span>
  );
}

function Metric({ label, value, tip, tone }) {
  return (
    <div className={`support-metric ${tone || ""}`} title={tip}>
      <small>{label}</small>
      <strong>{value ?? 0}</strong>
    </div>
  );
}

export function Support() {
  const { source: routeSource } = useParams();
  const [conversations, setConversations] = useState([]);
  const [turns, setTurns] = useState([]);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState(routeSource ? decodeURIComponent(routeSource) : "");
  const threadRef = useRef(null);
  const stickBottom = useRef(true);

  useEffect(() => {
    setSelected(routeSource ? decodeURIComponent(routeSource) : "");
  }, [routeSource]);

  useEffect(() => {
    let stop = false;
    async function load() {
      try {
        const list = await api("support/chats?limit=200");
        if (stop) return;
        setConversations(list.conversations || []);
        if (selected) {
          const transcript = await api(`support/chats/${encodeURIComponent(selected)}`);
          if (stop) return;
          setTurns(transcript.turns || []);
        } else {
          setTurns((list.chats || []).slice().reverse());
        }
        setError("");
      } catch (err) {
        if (!stop) setError(err.message);
      }
    }
    load();
    const timer = setInterval(load, 2500);
    return () => { stop = true; clearInterval(timer); };
  }, [selected]);

  useEffect(() => {
    const node = threadRef.current;
    if (!node || !stickBottom.current) return;
    node.scrollTop = node.scrollHeight;
  }, [turns]);

  const selectedMeta = useMemo(
    () => conversations.find((item) => item.source === selected) || null,
    [conversations, selected],
  );

  // Telemetry from the visible turns, so it works for the merged feed too.
  const stats = useMemo(() => {
    const s = { turns: turns.length, injections: 0, blocked: 0, redacted: 0, leaks: 0, misuse: 0,
      direct: 0, document: 0, tool_result: 0 };
    turns.forEach((t) => {
      if (t.injection) s.injections += 1;
      if (t.shield === "blocked") s.blocked += 1;
      if (t.shield === "redacted") s.redacted += 1;
      if (t.canary_leak) s.leaks += 1;
      if (t.tool_misuse) s.misuse += 1;
      if (t.vector && s[t.vector] !== undefined) s[t.vector] += 1;
    });
    return s;
  }, [turns]);

  const emptyList = !conversations.length && !error;

  return (
    <div className="support-page">
      <header className="support-head">
        <h1>Support agent chat</h1>
        <span className="soft">Live turns through Ray, the site&apos;s AI assistant. Defense verdicts show inline.</span>
        <Link className="support-back" to="/overview">← Overview</Link>
      </header>
      {error ? <p className="empty">{error}</p> : null}

      <div className="support-layout">
        <aside className="support-sidebar">
          <h2 className="support-pane-title">Conversations</h2>
          <ul className="support-conv-list">
            <li>
              <button type="button" className={!selected ? "active" : ""} onClick={() => setSelected("")}>
                <span className="support-conv-title">All recent turns</span>
                <span className="support-conv-meta">Merged live feed</span>
              </button>
            </li>
            {conversations.map((c) => {
              const name = agentLabel(c.source, c.user_agent);
              const bad = c.blocked || c.redacted || c.canary_leaks || c.contained;
              const warn = !bad && (c.injections || c.tool_misuse || c.flagged);
              return (
                <li key={c.source}>
                  <button type="button" className={selected === c.source ? "active" : ""}
                    onClick={() => setSelected(c.source)} title={c.source}>
                    <span className="support-conv-top">
                      <span className="support-conv-title">{name}</span>
                      {bad ? <span className="support-badge bad">flagged</span> : null}
                      {!bad && warn ? <span className="support-badge warn">watched</span> : null}
                      {!bad && !warn ? <span className="support-badge ok">clean</span> : null}
                    </span>
                    <span className="support-conv-meta">
                      {c.turns} turn{c.turns === 1 ? "" : "s"} · {formatTime(c.last_ts)}
                    </span>
                  </button>
                </li>
              );
            })}
            {emptyList ? <li className="empty">No support chats yet.</li> : null}
          </ul>
        </aside>

        <section className="support-main">
          <div className="support-main-head">
            <h2>{selected ? agentLabel(selected, selectedMeta?.user_agent) : "Recent turns"}</h2>
            <span className="soft">
              {selectedMeta ? `${selectedMeta.model || "—"} · ${selectedMeta.turns} turns` : "Newest at the bottom · live"}
            </span>
          </div>

          <div
            className="support-thread"
            ref={threadRef}
            onScroll={(event) => {
              const node = event.currentTarget;
              stickBottom.current = node.scrollHeight - node.scrollTop - node.clientHeight < 80;
            }}
          >
            {turns.map((turn) => {
              const verdict = labelTurn(turn);
              const who = agentLabel(turn.source, turn.user_agent);
              const parsed = splitReply(turn.reply);
              const tools = [...(turn.tools_used || []).map((t) => ({ name: t.name, args: t.args }))];
              parsed.calls.forEach((c) => {
                if (!tools.some((t) => t.name === c.name && JSON.stringify(t.args) === JSON.stringify(c.args))) tools.push(c);
              });
              const vector = VECTORS[turn.vector];
              return (
                <div className="support-turn" key={turn.id}>
                  {vector ? (
                    <div className={`support-banner vector ${turn.vector}`}>
                      <strong>{vector.banner}</strong>
                      <span>{verdict.detail}</span>
                    </div>
                  ) : verdict.tone !== "pass" ? (
                    <div className={`support-banner ${verdict.tone}`}>
                      <strong>{verdict.title}</strong>
                      <span>{verdict.detail}</span>
                    </div>
                  ) : null}

                  <div className="support-row customer">
                    <div className="support-bubble">
                      <div className="support-bubble-meta"><span>{who}</span><time>{formatTime(turn.ts)}</time></div>
                      <p>{turn.message || "(empty)"}</p>
                      {turn.document ? (
                        <details className={`support-attachment ${turn.vector === "document" ? "bad" : ""}`}>
                          <summary>📎 Attached document ({turn.document.length} chars)</summary>
                          <pre>{turn.document}</pre>
                        </details>
                      ) : null}
                    </div>
                    <div className="support-avatar customer" aria-hidden="true">{initials(who)}</div>
                  </div>

                  <div className="support-row assistant">
                    <div className="support-avatar assistant" aria-hidden="true">R</div>
                    <div className={`support-bubble ${verdict.tone !== "pass" ? verdict.tone : ""}`}>
                      <div className="support-bubble-meta"><span>Ray · support</span><time>{formatTime(turn.ts)}</time></div>
                      {tools.length ? (
                        <div className="support-tools">{tools.map((t, i) => <ToolChip tool={t} key={i} />)}</div>
                      ) : null}
                      <p>{parsed.text || (tools.length ? "(tool call only)" : "(no reply recorded)")}</p>
                    </div>
                  </div>
                </div>
              );
            })}
            {!turns.length && !error ? <p className="empty">Waiting for a support conversation.</p> : null}
          </div>
        </section>

        <aside className="support-telemetry">
          <h2 className="support-pane-title">Telemetry {selectedMeta ? "" : <span className="soft">· all turns</span>}</h2>
          <div className="support-metrics">
            <Metric label="Turns" value={stats.turns} tip="Turns shown in the thread." />
            <Metric label="Injections" value={stats.injections} tip="Turns where an embedded or direct instruction was detected." tone={stats.injections ? "warn" : ""} />
            <Metric label="Blocked" value={stats.blocked} tip="Stopped at the gate before reaching the model." tone={stats.blocked ? "bad" : ""} />
            <Metric label="Withheld" value={stats.redacted} tip="Replies withheld because they leaked restricted data." />
            <Metric label="Canary leaks" value={stats.leaks} tip="Planted credential appeared in a reply." tone={stats.leaks ? "bad" : ""} />
            <Metric label="Tool misuse" value={stats.misuse} tip="Assistant used a tool on internal data." />
          </div>
          <h3 className="support-sub">Where the injection came from</h3>
          <div className="support-vectors">
            {Object.entries(VECTORS).map(([key, v]) => (
              <div key={key} className={`support-vector ${stats[key] ? "hit" : ""}`} title={v.banner}>
                <span>{v.label}</span><strong>{stats[key]}</strong>
              </div>
            ))}
          </div>
          <dl className="support-facts">
            <div><dt>Model</dt><dd className="mono">{selectedMeta?.model || turns[turns.length - 1]?.model || "—"}</dd></div>
            {selectedMeta ? (
              <>
                <div><dt>Status</dt><dd>{selectedMeta.flagged ? (selectedMeta.session ? `Contained · ${selectedMeta.session}` : "Flagged") : "Clean"}</dd></div>
                <div><dt>Seen</dt><dd>{formatTime(selectedMeta.first_ts)} → {formatTime(selectedMeta.last_ts)}</dd></div>
                <div><dt>User-Agent</dt><dd className="mono">{selectedMeta.user_agent || "—"}</dd></div>
              </>
            ) : null}
          </dl>
          <div className="support-spark-wrap">
            <small title="One mark per turn: grey delivered, indigo flagged, amber withheld, red blocked/leak.">Verdict timeline</small>
            <div className="support-spark">
              {turns.map((turn) => (
                <i key={turn.id} className={sparkTone(turn)} title={`${formatTime(turn.ts)} · ${labelTurn(turn).title}`} />
              ))}
              {!turns.length ? <span className="soft">No turns</span> : null}
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}
