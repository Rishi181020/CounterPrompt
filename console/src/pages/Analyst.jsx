import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { useConsole } from "../App";
import { Markdown } from "../markdown";

const suggestions = [
  "What was it after?",
  "How do we stop this? Give remediation steps",
  "Which credentials were exposed?",
];

function chatKey(id) {
  return `counterprompt:analyst:${id}`;
}

function readChat(id) {
  try {
    const value = JSON.parse(localStorage.getItem(chatKey(id)) || "[]");
    return Array.isArray(value) ? value : [];
  } catch {
    return [];
  }
}

export function Analyst() {
  const { id } = useParams();
  const { state } = useConsole();
  const sessions = state?.sessions || [];
  const chosen = id || sessions[0]?.session;
  const [messages, setMessages] = useState([]);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const thread = useRef(null);

  useEffect(() => {
    setMessages(chosen ? readChat(chosen) : []);
    setError("");
  }, [chosen]);

  useEffect(() => {
    if (thread.current) thread.current.scrollTop = thread.current.scrollHeight;
  }, [messages, busy]);

  async function send(text) {
    const question = text.trim();
    if (!question || !chosen || busy) return;
    const next = [...messages, { role: "user", content: question }];
    setMessages(next);
    setDraft("");
    setBusy(true);
    setError("");
    localStorage.setItem(chatKey(chosen), JSON.stringify(next));
    try {
      const result = await api("ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session: chosen, messages: next }),
      });
      const saved = [...next, { role: "assistant", content: result.answer, reasoning: result.reasoning || "" }];
      setMessages(saved);
      localStorage.setItem(chatKey(chosen), JSON.stringify(saved));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  if (!chosen) return <main><p className="empty">No sessions are available.</p></main>;
  return (
    <div className="analyst-layout">
      <aside className="session-list">
        <h2>Sessions</h2>
        {sessions.map((session) => (
          <Link key={session.session} className={session.session === chosen ? "active" : ""} to={`/analyst/${session.session}`}>
            <b className="mono">{session.session}</b>
            <small>{session.reason}, depth {session.depth || 0}</small>
          </Link>
        ))}
      </aside>
      <section className="chat">
        <div>
          <h1 className="section-title">Ask about <span className="mono">{chosen}</span></h1>
        </div>
        <div className="chat-thread" ref={thread}>
          {messages.map((message, index) => (
            <div className={message.role === "user" ? "bubble user" : "bubble assistant"} key={index}>
              {message.role === "user" ? <p>{message.content}</p> : <Markdown text={message.content} />}
              {message.reasoning ? <details><summary>Show reasoning</summary><p>{message.reasoning}</p></details> : null}
            </div>
          ))}
          {!messages.length && <p className="empty">Ask a question to begin.</p>}
          {busy ? <p>Thinking…</p> : null}
        </div>
        {!messages.length && (
          <div className="suggestions">
            {suggestions.map((item) => (
              <button className="btn" key={item} type="button" onClick={() => send(item)}>{item}</button>
            ))}
          </div>
        )}
        {error ? <p className="chat-error">{error}</p> : null}
        <form className="chat-form" onSubmit={(event) => { event.preventDefault(); send(draft); }}>
          <textarea
            value={draft}
            placeholder="Ask about this incident"
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                send(draft);
              }
            }}
          />
          <button className="btn primary" type="submit" disabled={busy}>Ask</button>
        </form>
      </section>
    </div>
  );
}
