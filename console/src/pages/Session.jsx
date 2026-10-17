import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, formatTime, pageSummary } from "../api";
import { useConsole } from "../App";

function post(path, payload) {
  return api(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

function stepNote(event) {
  if (!event) return "No request selected.";
  const gap = event.gap_s == null ? "First request from this source." : `${event.gap_s}s since the previous request.`;
  return `${gap} ${event.asset ? "Asset" : "Document"}. ${event.has_accept ? "Accept present" : "No Accept"}. ${event.has_sec_fetch ? "Sec-Fetch present" : "No Sec-Fetch"}.`;
}

export function Session() {
  const { id } = useParams();
  const { state } = useConsole();
  const sessions = state?.sessions || [];
  const chosen = id || sessions[0]?.session;
  const [detail, setDetail] = useState(null);
  const [step, setStep] = useState(0);
  const [summary, setSummary] = useState("");
  const [pageHtml, setPageHtml] = useState("");
  const [open, setOpen] = useState(false);
  const [showSource, setShowSource] = useState(false);
  const [error, setError] = useState("");
  const [rules, setRules] = useState([]);
  const [benign, setBenign] = useState(false);
  const dialog = useRef(null);
  const threadRef = useRef(null);
  const liveCount = useRef(-1);

  useEffect(() => {
    const node = threadRef.current?.querySelector(".step.selected");
    if (node) node.scrollIntoView({ block: "nearest" });
  }, [step, detail]);

  useEffect(() => {
    if (!chosen) return;
    let stop = false;
    setStep(0);
    liveCount.current = -1;
    api("session/" + encodeURIComponent(chosen))
      .then((next) => {
        if (stop) return;
        liveCount.current = (next?.events || []).length;
        setDetail(next);
      })
      .catch((err) => { if (!stop) setError(err.message); });
    api("rules").then((next) => { if (!stop) setRules(Array.isArray(next?.rules) ? next.rules : []); }).catch(() => {});
    return () => { stop = true; };
  }, [chosen]);

  // Live tail: the shell WebSocket refreshes `state` on every proxy push; use
  // that as the tick to grow the open thread while an attack is flowing in.
  // Keeps the reader's place; only follows the tail when already on it.
  useEffect(() => {
    if (!chosen || !state || liveCount.current < 0) return;
    let stop = false;
    api("session/" + encodeURIComponent(chosen))
      .then((next) => {
        if (stop) return;
        const count = (next?.events || []).length;
        const previous = liveCount.current;
        if (count === previous) return;
        liveCount.current = count;
        setDetail(next);
        setStep((current) => (previous > 0 && current >= previous - 1 ? count - 1 : current));
      })
      .catch(() => {});
    return () => { stop = true; };
  }, [state]);

  useEffect(() => {
    const source = detail?.session?.source;
    if (!source) return;
    let stop = false;
    api("allowlist")
      .then((next) => { if (!stop) setBenign((Array.isArray(next?.allowlist) ? next.allowlist : []).some((row) => row.source === source)); })
      .catch(() => {});
    return () => { stop = true; };
  }, [detail]);

  const applyRule = (path) => {
    post("rules", { path, action: "block" })
      .then((next) => setRules(Array.isArray(next?.rules) ? next.rules : []))
      .catch(() => {});
  };
  const removeRule = (path) => {
    api("rules?path=" + encodeURIComponent(path), { method: "DELETE" })
      .then((next) => setRules(Array.isArray(next?.rules) ? next.rules : []))
      .catch(() => {});
  };
  const markBenign = () => {
    const source = detail?.session?.source;
    if (!source) return;
    post("allowlist", { source, note: "Marked benign from session " + chosen })
      .then(() => setBenign(true))
      .catch(() => {});
  };

  const events = detail?.events || [];
  const selected = events[step] || events[0];
  const lastTs = events.length ? Date.parse(events[events.length - 1].ts) : 0;
  const isLive = Boolean(lastTs) && Date.now() - lastTs < 20000;
  const trap = Math.max(0, events.findIndex((event) => event.route_type === "trap"));
  const telemetry = detail?.metadata?.telemetry || {};
  const checkin = detail?.metadata?.checkin || {};
  const who = [checkin.model, checkin.operator].filter(Boolean).join(", ");
  const analysis = detail?.analysis?.analysis || {};
  const outcome = sessions.find((item) => item.session === chosen)?.outcome || "flagged";
  const suggested = analysis.block_rules || detail?.rules || [];
  const activePaths = new Set(rules.map((rule) => rule.path));

  useEffect(() => {
    if (!selected || !["trap", "maze", "credential_reuse"].includes(selected.route_type)) {
      setSummary("");
      setPageHtml("");
      return;
    }
    const path = (selected.path || "").split("?")[0] || selected.normalized_path;
    let stop = false;
    api(`session/${encodeURIComponent(chosen)}/page?path=${encodeURIComponent(path)}`)
      .then((html) => {
        if (stop) return;
        const clean = String(html || "").trim().replace(/^```[\w-]*\s*/, "").replace(/\s*```$/, "");
        setPageHtml(clean);
        setSummary(pageSummary(clean));
      })
      .catch(() => { if (!stop) setSummary("—"); });
    return () => { stop = true; };
  }, [chosen, selected]);

  useEffect(() => {
    const node = dialog.current;
    if (!node) return;
    if (open && !node.open) node.showModal();
    if (!open && node.open) node.close();
  }, [open]);
  if (!chosen) return <p className="empty">No sessions have been caught.</p>;
  if (error) return <p className="empty">{error}</p>;
  if (!detail || detail.session?.session !== chosen) return <p className="empty">Loading session.</p>;

  return (
    <div className="session-page">
      <p><Link to="/sessions">Sessions</Link> / <span className="mono">{chosen}</span></p>
      <h1 className="page-title">
        {events.length
          ? `It made ${events.length} requests${detail.depth ? ", then followed the trap into the maze." : "."}`
          : "This source was flagged before a request was recorded."}
      </h1>
      <div className="facts">
        <div><small>Caught by</small><b>{detail.session.reason}</b></div>
        <div><small>Outcome</small><b>{outcome}</b></div>
        <div><small>Maze depth</small><b>{detail.depth || 0}</b></div>
        <div><small>Time to detect</small><b>{telemetry.time_to_detect_s == null ? "—" : `${telemetry.time_to_detect_s}s`}</b></div>
        <div><small>Median gap</small><b>{telemetry.median_gap_s == null ? "—" : `${telemetry.median_gap_s}s${telemetry.mechanical ? ", mechanical" : ""}`}</b></div>
        <div><small>Asset loads</small><b>{telemetry.asset_requests || 0} assets, {telemetry.document_requests || 0} documents{telemetry.agent_shaped ? ", agent-shaped" : ""}</b></div>
        {who ? <div><small>Check-in</small><b>{who}</b></div> : null}
      </div>
      <div className="grid thread-grid">
        <section className="thread-col">
          <h2>The thread {isLive ? <span className="live-pill">live</span> : null}</h2>
          <div className="thread-scroll" ref={threadRef}>
            <div className="thread">
              {events.map((event, index) => (
                <div key={event.id || index}>
                  {index === trap ? <div className="trap-wall">Caught here. Every step below was fabricated.</div> : null}
                  <button className={index === step ? "step selected" : "step"} type="button" onClick={() => setStep(index)}>
                    <time>{formatTime(event.ts)}</time>
                    <span className="mono">{event.method} {event.normalized_path || event.path}<small>{event.route_type || event.kind}</small></span>
                  </button>
                </div>
              ))}
            </div>
          </div>
        </section>
        <aside className="panel inspector">
          <h2>Step {String(step + 1).padStart(2, "0")}</h2>
          <p>{stepNote(selected)}</p>
          <div className="request-pair">
            <div><b>It asked for</b><pre>{selected ? `${selected.method} ${selected.path}` : "—"}</pre></div>
            <div>
              <b>We served</b>
              <pre>{summary || "—"}</pre>
              {pageHtml ? <button className="linkish" type="button" onClick={() => { setShowSource(false); setOpen(true); }}>View page</button> : null}
            </div>
          </div>
        </aside>
      </div>
      <div className="split">
        <section>
          <div className="section-head"><h2>Suggested block rules</h2></div>
          <table>
            <tbody>
              {suggested.map((rule) => (
                <tr key={rule.path}>
                  <td className="mono">{rule.path}</td>
                  <td>{rule.action}</td>
                  <td>
                    {activePaths.has(rule.path)
                      ? <span className="empty">Active</span>
                      : <button className="linkish" type="button" onClick={() => applyRule(rule.path)}>Apply</button>}
                  </td>
                </tr>
              ))}
              {!suggested.length && <tr><td className="empty">No suggested rules.</td></tr>}
            </tbody>
          </table>
          <div className="section-head"><h2>Active rules</h2></div>
          <table>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.path}>
                  <td className="mono">{rule.path}</td>
                  <td>{rule.action}</td>
                  <td><button className="linkish" type="button" onClick={() => removeRule(rule.path)}>Remove</button></td>
                </tr>
              ))}
              {!rules.length && <tr><td className="empty">No active rules.</td></tr>}
            </tbody>
          </table>
        </section>
        <section>
          <div className="section-head"><h2>Analyst</h2></div>
          <p>{analysis.summary || "Ask about the evidence and what to change."}</p>
          <Link className="btn primary" to={`/analyst/${chosen}`}>Open analyst chat</Link>
          {" "}
          <a className="btn" href={`/_counterprompt/api/session/${chosen}/report.md`} download>Export report</a>
          <p className="lede">
            {benign
              ? "This source is allowlisted. It is logged but never flagged or mazed."
              : "Was this an authorized pentest or a benign monitor?"}
          </p>
          {benign
            ? <span className="empty">Allowlisted</span>
            : <button className="linkish" type="button" onClick={markBenign}>Mark source benign</button>}
        </section>
      </div>
      <dialog className="page-modal" ref={dialog} onClose={() => setOpen(false)} onClick={(event) => { if (event.target === dialog.current) setOpen(false); }}>
        {open ? (
          <>
            <header>
              <span className="mono">{(selected?.path || "").split("?")[0]}</span>
              <span>
                <button className="linkish" type="button" onClick={() => setShowSource((value) => !value)}>{showSource ? "Hide source" : "Show source"}</button>
                {" "}
                <button className="linkish" type="button" onClick={() => setOpen(false)}>Close</button>
              </span>
            </header>
            {showSource ? <pre>{pageHtml}</pre> : <iframe title="Served page" sandbox="" srcDoc={pageHtml} />}
          </>
        ) : null}
      </dialog>
    </div>
  );
}
