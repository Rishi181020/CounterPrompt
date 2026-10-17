import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, shortSource } from "../api";
import { useConsole } from "../App";

function seeded(seed) {
  let x = [...seed].reduce((n, c) => (Math.imul(n, 31) + c.charCodeAt(0)) >>> 0, 2166136261);
  return () => {
    x = Math.imul(x ^ (x >>> 15), 1 | x);
    x ^= x + Math.imul(x ^ (x >>> 7), 61 | x);
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
}

const INK = "#18202b";
const MUTED = "#6b7280";
const RED = "#cf3b2c";
const BLUE = "#2f3f8f";
const TOKEN = "#7c3aed";

const COLS = 14;
const ROWS = 8;
const CELL = 32;
const X0 = 392;
const Y0 = 40;
const WALL = X0 - 24;

const TRIGGERS = {
  trap_path: "followed robots.txt Disallow",
  credential_exfil: "exfiltrated a credential via prompt injection",
  agent_checkin: "agent self-identified",
  manual: "flagged by an analyst",
};
function triggerText(reason, event) {
  if (TRIGGERS[reason]) return TRIGGERS[reason];
  if (/canary/i.test(reason || "")) return "used a planted canary credential";
  if (/inject|jailbreak|prompt/i.test(reason || "")) return "prompt injection";
  return reason || event?.kind || "trap";
}

function clock(ts) {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
const clip = (s, n) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

// Perfect maze + depth-first tour. Every fabricated page claims the next new cell
// on the tour, so the drawn route follows real corridors, doubling back at dead ends.
function buildMaze(seed) {
  const rand = seeded(seed);
  const seen = new Set(["0,0"]);
  const stack = [[0, 0]];
  const open = new Set();
  const tour = [[0, 0]];
  const firstVisit = [0];
  while (stack.length) {
    const [x, y] = stack.at(-1);
    const choices = [[x + 1, y], [x - 1, y], [x, y + 1], [x, y - 1]].filter(
      ([a, b]) => a >= 0 && b >= 0 && a < COLS && b < ROWS && !seen.has(`${a},${b}`)
    );
    if (!choices.length) {
      stack.pop();
      if (stack.length) tour.push(stack.at(-1));
      continue;
    }
    const next = choices[Math.floor(rand() * choices.length)];
    open.add(`${x},${y}:${next[0]},${next[1]}`);
    open.add(`${next[0]},${next[1]}:${x},${y}`);
    seen.add(`${next[0]},${next[1]}`);
    stack.push(next);
    tour.push(next);
    firstVisit.push(tour.length - 1);
  }
  let walls = "";
  for (let y = 0; y < ROWS; y += 1) {
    for (let x = 0; x < COLS; x += 1) {
      const px = X0 + x * CELL;
      const py = Y0 + y * CELL;
      if (x < COLS - 1 && !open.has(`${x},${y}:${x + 1},${y}`)) walls += `M${px + CELL} ${py}v${CELL}`;
      if (y < ROWS - 1 && !open.has(`${x},${y}:${x},${y + 1}`)) walls += `M${px} ${py + CELL}h${CELL}`;
    }
  }
  return { walls, tour, firstVisit };
}
const center = ([cx, cy]) => [X0 + cx * CELL + CELL / 2, Y0 + cy * CELL + CELL / 2];

function analyse(trail, flag) {
  const events = trail.map((e, i) => ({ ...e, n: i + 1 }));
  const caughtIdx = events.findIndex((e) => e.session === flag.session);
  const before = caughtIdx === -1 ? events : events.slice(0, caughtIdx);
  const after = caughtIdx === -1 ? [] : events.slice(caughtIdx);
  const steps = [];
  for (const e of after) {
    if (e.kind === "credential_reuse") {
      if (steps.length) steps.at(-1).token = e;
      continue;
    }
    steps.push({ ...e });
  }
  return { before, caught: after[0] || null, steps, leaked: after.filter((e) => e.route_type === "passthrough").length };
}

export function MazeMap({ sessions }) {
  const { state } = useConsole() || {};
  const [chosen, setChosen] = useState("");
  const [trail, setTrail] = useState(null);
  const [error, setError] = useState("");
  const [shown, setShown] = useState(0);
  const session = sessions.find((s) => s.session === chosen) || sessions[0];
  const sessionId = session?.session || "";
  const refreshKey = state?.kpis?.requests;

  useEffect(() => { setShown(0); setTrail(null); }, [sessionId]);
  useEffect(() => {
    if (!sessionId) return undefined;
    let stop = false;
    api(`session/${encodeURIComponent(sessionId)}/trail`)
      .then((next) => { if (!stop) { setTrail(next); setError(""); } })
      .catch((err) => { if (!stop) setError(err.message); });
    return () => { stop = true; };
  }, [sessionId, refreshKey]);

  const maze = useMemo(() => buildMaze(sessionId || "counterprompt"), [sessionId]);
  const view = useMemo(() => (trail ? analyse(trail.events || [], trail.flag || {}) : null), [trail]);
  const capacity = maze.firstVisit.length;
  const total = view ? Math.min(view.steps.length, capacity) : 0;

  // Replay: reveal one real step at a time; new live steps continue the replay.
  useEffect(() => {
    if (shown >= total) return undefined;
    const t = setTimeout(() => setShown((s) => s + 1), shown === 0 ? 700 : 450);
    return () => clearTimeout(t);
  }, [shown, total]);

  if (!sessions.length) {
    return <p className="empty">No agent has been caught yet. When one trips a trap, its real path into the maze is drawn here.</p>;
  }

  const selector = sessions.length > 1 && (
    <label className="maze-select">
      Agent{" "}
      <select value={sessionId} onChange={(e) => setChosen(e.target.value)}>
        {sessions.map((s) => (
          <option key={s.session} value={s.session}>{shortSource(s.source)} · {s.session} · {s.reason}</option>
        ))}
      </select>
    </label>
  );
  if (error) return <>{selector}<p className="empty">Could not load this agent's trail: {error}</p></>;
  if (!view) return <>{selector}<p className="empty">Loading the agent's trail.</p></>;

  const { before, caught, steps, leaked } = view;

  // Left: the real pages, in order (last 12 if longer), laid out as a snake.
  const left = before.slice(-12);
  const hiddenLeft = before.length - left.length;
  const box = (i) => {
    const row = Math.floor(i / 3);
    const col = row % 2 ? 2 - (i % 3) : i % 3;
    return [18 + col * 114, 46 + row * 52];
  };
  const leftPts = left.map((_, i) => { const [x, y] = box(i); return [x + 48, y + 16]; });
  const crossY = Y0 + CELL / 2;
  const lastLeft = leftPts.at(-1);
  // Lead from the last real page to the trap point on the divider, routed in a
  // gutter so it never crosses another box.
  let lead = "";
  if (lastLeft) {
    const [lx, ly] = lastLeft;
    const gx = WALL - 10;
    lead = lx >= 18 + 2 * 114 + 48
      ? `M${lx + 48} ${ly}H${gx}V${crossY}H${WALL}`
      : `M${lx} ${ly + 16}V${ly + 26}H${gx}V${crossY}H${WALL}`;
  }

  // Right: one maze cell per fabricated page served.
  const tourEnd = shown > 0 ? maze.firstVisit[shown - 1] : 0;
  const route = maze.tour.slice(0, tourEnd + 1).map(center);
  const routeD = shown > 0 ? `M${WALL} ${crossY}H${X0}` + route.map(([x, y]) => `L${x} ${y}`).join("") : "";
  const tokens = steps.filter((s) => s.token).length;
  const height = Y0 + ROWS * CELL + 46;
  const overflow = steps.length - total;

  return (
    <div className="maze-live">
      <div className="maze-toolbar">
        {selector}
        <span className="maze-summary">
          {before.length} real request{before.length === 1 ? "" : "s"}
          {caught ? <> → caught at <b>#{caught.n}</b> ({triggerText(trail.flag.reason, caught)})</> : " · not caught yet"}
          {" "}→ <b>{steps.length}</b> fabricated page{steps.length === 1 ? "" : "s"}
          {tokens ? <>, <b style={{ color: TOKEN }}>{tokens}</b> fake password use{tokens === 1 ? "" : "s"}</> : null}
          {" · "}<span style={{ color: leaked ? RED : "#15803d" }}>{leaked} reached the real app after the catch</span>
        </span>
        <button type="button" className="btn maze-replay" onClick={() => setShown(0)}>Replay</button>
      </div>
      <svg viewBox={`0 0 880 ${height}`} role="img" className="maze-map"
        aria-label={`Agent made ${before.length} real requests, was caught, then was served ${steps.length} fabricated pages`}>
        <text x="18" y="24" fontSize="11" fontWeight="600" letterSpacing="0.08em" fill={MUTED}>YOUR REAL SITE · BEFORE DETECTION</text>
        <text x={X0} y="24" fontSize="11" fontWeight="600" letterSpacing="0.08em" fill={BLUE}>FABRICATED PAGES · ONE CELL PER PAGE SERVED</text>

        {leftPts.length > 1 && <polyline points={leftPts.map((p) => p.join(",")).join(" ")} fill="none" stroke={RED} strokeWidth="2" strokeLinejoin="round" />}
        {lead && <path d={lead} fill="none" stroke={RED} strokeWidth="2" strokeLinejoin="round" />}
        {left.map((e, i) => {
          const [x, y] = box(i);
          return (
            <g key={e.id}>
              <rect x={x} y={y} width="96" height="32" rx="6" fill="#fff" stroke="#c9ced6" />
              <text x={x + 6} y={y + 12} fontSize="8.5" fill={MUTED}>#{e.n} · {e.status}</text>
              <text x={x + 6} y={y + 25} fontSize="10.5" fill={INK} fontFamily='"DM Mono", monospace'>{clip(`${e.method === "GET" ? "" : e.method + " "}${e.path}`, 15)}</text>
              <title>{`#${e.n} ${e.method} ${e.path} → ${e.status} (real app) at ${clock(e.ts)}`}</title>
            </g>
          );
        })}
        {hiddenLeft > 0 && <text x="18" y="40" fontSize="10" fill={MUTED}>+{hiddenLeft} earlier requests</text>}
        {!left.length && <text x="18" y="70" fontSize="11.5" fill={MUTED}>No real pages: caught on its first request.</text>}

        <line x1={WALL} y1="34" x2={WALL} y2={Y0 + ROWS * CELL + 4} stroke={INK} strokeWidth="3" strokeLinecap="round" />
        {caught && (
          <g>
            <rect x="18" y={height - 40} width={WALL - 34} height="32" rx="6" fill="#fdf0ee" stroke={RED} />
            <text x="28" y={height - 27} fontSize="10" fontWeight="700" fill={RED}>TRAP · REQUEST #{caught.n} · {clock(caught.ts)}</text>
            <text x="28" y={height - 14} fontSize="10.5" fill={INK}>
              {clip(`${caught.method} ${caught.path}: ${triggerText(trail.flag.reason, caught)}`, 56)}
            </text>
            <circle cx={WALL} cy={crossY} r="6" fill={RED} stroke="#fff" strokeWidth="2" />
          </g>
        )}

        <rect x={X0} y={Y0} width={COLS * CELL} height={ROWS * CELL} fill="#f3f5fb" />
        <path d={`M${X0} ${Y0 + CELL}V${Y0 + ROWS * CELL}H${X0 + COLS * CELL}V${Y0}H${X0}`} fill="none" stroke={BLUE} strokeOpacity="0.7" strokeWidth="2" />
        <text x={X0 + 4} y={Y0 - 4} fontSize="9" fill={BLUE}>entrance ↓</text>
        <path d={maze.walls} fill="none" stroke={BLUE} strokeOpacity="0.5" strokeWidth="1.5" strokeLinecap="round" />
        {routeD && <path d={routeD} fill="none" stroke={RED} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" opacity="0.85" />}
        {steps.slice(0, shown).map((s, i) => {
          const [x, y] = center(maze.tour[maze.firstVisit[i]]);
          const head = i === shown - 1;
          return (
            <g key={s.id} className={head ? "maze-head" : undefined}>
              {s.token
                ? <rect x={x - 7} y={y - 7} width="14" height="14" fill={TOKEN} stroke="#fff" strokeWidth="1.5" transform={`rotate(45 ${x} ${y})`} />
                : <circle cx={x} cy={y} r={head ? 8 : 7} fill={head ? RED : "#fff"} stroke={RED} strokeWidth="1.5" />}
              <text x={x} y={y + 3} fontSize="8" textAnchor="middle" fill={head || s.token ? "#fff" : RED} fontWeight="700">{i + 1}</text>
              <title>{`Fake page ${i + 1} (request #${s.n}) · ${s.method} ${s.path} · ${clock(s.ts)}${s.token ? " · planted fake password used here" : ""}`}</title>
            </g>
          );
        })}
        {shown > 0 && steps[shown - 1] && (() => {
          const [x, y] = center(maze.tour[maze.firstVisit[shown - 1]]);
          const right = x > X0 + COLS * CELL - 150;
          return <text x={right ? x - 12 : x + 12} y={y - 10} fontSize="10.5" textAnchor={right ? "end" : "start"} fill={INK}
            fontFamily='"DM Mono", monospace' className="maze-label">{clip(steps[shown - 1].path, 30)}</text>;
        })()}
        <text x={X0} y={Y0 + ROWS * CELL + 18} fontSize="11" fill={MUTED}>
          {overflow > 0 ? `Showing the first ${total} of ${steps.length} pages. ` : ""}No exit: every link leads to another fake page.
        </text>
      </svg>
      <div className="maze-legend">
        <span><i className="dot-real" />real page (hover for details)</span>
        <span><i className="dot-fake" />fabricated page, numbered in order</span>
        <span><i className="dot-token" />planted fake password used</span>
        <Link to={`/sessions/${sessionId}`}>Full replay →</Link>
      </div>
    </div>
  );
}
