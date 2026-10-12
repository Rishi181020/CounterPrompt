import { createContext, useContext, useEffect, useState } from "react";
import { HashRouter, NavLink, Navigate, Route, Routes } from "react-router-dom";
import { api } from "./api";
import { Overview } from "./pages/Overview";
import { Session } from "./pages/Session";
import { Analyst } from "./pages/Analyst";
import { Canaries } from "./pages/Canaries";
import { Team } from "./pages/Team";
import { Support } from "./pages/Support";

const Console = createContext(null);
export function useConsole() {
  return useContext(Console);
}

const links = [
  ["overview", "Overview"],
  ["sessions", "Sessions"],
  ["analyst", "Analyst"],
  ["canaries", "Canaries"],
  ["support", "Support"],
  ["team", "Team"],
];

function Frame() {
  const [state, setState] = useState(null);
  const [canaries, setCanaries] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    let ws = null;
    let retry = null;
    let poll = null;
    let closed = false;

    async function pollOnce() {
      try {
        const [nextState, nextCanaries] = await Promise.all([
          api("state"),
          api("canaries"),
        ]);
        if (closed) return;
        setState(nextState);
        setCanaries(nextCanaries.canaries || []);
        setError("");
      } catch (err) {
        if (!closed) setError(err.message);
      }
    }
    function startPolling() {
      if (!poll) {
        pollOnce();
        poll = setInterval(pollOnce, 8000);
      }
    }
    function stopPolling() {
      clearInterval(poll);
      poll = null;
    }
    function connect() {
      const scheme = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${scheme}://${location.host}/_counterprompt/ws`);
      const ping = setInterval(() => {
        if (ws.readyState === 1) ws.send("ping");
      }, 10000);
      ws.onopen = () => {
        stopPolling();
        setError("");
      };
      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.state) setState(payload.state);
          if (payload.canaries) setCanaries(payload.canaries);
        } catch { /* ignore malformed frames */ }
      };
      ws.onclose = () => {
        clearInterval(ping);
        if (closed) return;
        startPolling();
        retry = setTimeout(connect, 3000);
      };
      ws.onerror = () => { try { ws.close(); } catch { /* already closed */ } };
    }
    connect();
    return () => {
      closed = true;
      clearTimeout(retry);
      stopPolling();
      if (ws) ws.close();
    };
  }, []);

  return (
    <Console.Provider value={{ state, canaries }}>
      <header className="shell">
        <a className="brand" href="#/overview">
          <svg className="mark" viewBox="0 0 16 16" aria-hidden="true">
            <rect x="1" y="1" width="12" height="12" fill="none" stroke="#18202b" />
            <path d="M4 4h8v8H4z" fill="none" stroke="#2f3f8f" />
            <path d="M6 7h4v2H6z" fill="#cf3b2c" />
          </svg>
          counterprompt
        </a>
        <nav className="nav" aria-label="Console">
          {links.map(([path, label]) => (
            <NavLink key={path} to={"/" + path}>{label}</NavLink>
          ))}
        </nav>
        <div className="shell-actions">
          <span className="protection">{state?.enabled === false ? "Protection off" : "Protection on"}</span>
          {state?.dry_run ? <span className="protection dry-run">Dry run</span> : null}
        </div>
      </header>
      {error ? <main><p className="empty">{error}</p></main> : (
        <Routes>
          <Route path="/" element={<Navigate to="/overview" replace />} />
          <Route path="/overview" element={<main><Overview /></main>} />
          <Route path="/sessions/:id?" element={<main><Session /></main>} />
          <Route path="/analyst/:id?" element={<Analyst />} />
          <Route path="/canaries" element={<main><Canaries /></main>} />
          <Route path="/support/:source?" element={<main><Support /></main>} />
          <Route path="/team" element={<main><Team /></main>} />
        </Routes>
      )}
    </Console.Provider>
  );
}

export function App() {
  return (
    <HashRouter>
      <Frame />
    </HashRouter>
  );
}
