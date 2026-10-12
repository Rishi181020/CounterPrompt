# Counterprompt Console — UI build plan

How to turn the six concept screens (Overview, Session replay, Labyrinth, Canaries, Scoreboard, Direction, plus Stage mode) into the real console that ships with the proxy. The current console is one file — `dashboard/index.html`, Chart.js, polling. This plan replaces it with the new design and wires every screen to data that already exists in the API, calling out exactly what's live today vs. what needs a backend change first.

Keep it one self-contained build. No framework, no bundler — the console is served as static files by Flask (`send_file`) and talks to the existing `/_counterprompt/api/*` endpoints. That's the whole point: drop-in, no deps.

Reference screens (pixel spec): `assets/` concept images — Overview, Session replay, Labyrinth, Canaries (Canary Studio), Deterrence Scoreboard.

## 0. The design, in tokens

```css
:root{
  --vellum:#E8ECE9;    /* page ground            */
  --sheet:#F7F9F7;     /* cards, panels          */
  --ink:#18202B;       /* text, walls, hero      */
  --graphite:#56616B;  /* secondary text, labels */
  --rule:#C3CCC7;      /* hairlines, grid        */
  --thread:#CF3B2C;    /* ATTACKER — nothing else */
  --indigo:#2F3F8F;    /* Counterprompt defences  */
  --thread-ink:#B4291D;/* thread text on light   */
}
```

- Type: Archivo (variable, use the width axis — Expanded 800 for headlines, normal for body, 87% for labels) + DM Mono for paths, IDs, payloads. Tabular figures everywhere numbers line up.
- Rules of the house: red = the attacker, only ever. Real vs. fabricated is solid ink vs. indigo 45° hatch. Structure with hairlines and space, not boxes and shadows. Headlines are sentences that state what happened.
- Light mode only is fine for v1; if you add dark mode, define the tokens again under `@media (prefers-color-scheme: dark)` and keep the thread red.

## 1. Architecture

### 1.1 File layout

```
dashboard/
├── index.html         # shell: <header> nav + <main id="view">
├── console.css        # tokens + components (replaces inline <style>)
├── console.js         # router, fetch layer, render functions
├── maze-map.js        # the hero floor-plan generator (see 3.1)
└── fonts/             # self-hosted Archivo + DM Mono woff2 (offline demo)
```

Serve them: the proxy already does `send_file(... "dashboard"/"index.html")` for `/_counterprompt`; add routes (or a static folder) for the css/js/fonts, or inline css+js into `index.html` to keep the single-file property. For the hackathon, inline is safer — one file, no path/MIME surprises on stage.

### 1.2 Client-side routing

Six views behind hash routes, one top nav (no sidebar): `#/overview` `#/sessions/:id?` `#/labyrinth/:id?` `#/canaries` `#/scoreboard` `#/direction`. On `hashchange`, call the matching `render*()`. Keep a single state object; each render reads from it. No framework needed.

### 1.3 Data layer

One `api(path)` helper (fetch + JSON + error toast). A `poll()` that refreshes the active view's data on an interval; swap to SSE later (6.2). Everything the UI needs maps to endpoints that already exist — see §4 for the gaps.

## 2. Build order (each screen is a vertical slice)

| # | Screen | Depends on | Live data today? |
|---|---|---|---|
| 1 | Shell + nav + tokens | — | n/a |
| 2 | Overview | /api/state, /api/scoreboard | mostly (see 4.1) |
| 3 | Session replay | /api/session/:id, /api/run/:id | yes |
| 4 | Labyrinth | /api/session/:id | partial (see 4.2) |
| 5 | Scoreboard | /api/scoreboard | yes |
| 6 | Canaries | — (new endpoint) | no (see 4.3) |
| 7 | Direction / Stage | static | n/a (static copy) |

## 3. Screen-by-screen

### 3.1 Shell + Overview (priority: high)
- Shell: sticky `<header>` with the logo mark (inline SVG from the concept), the six nav links, a target picker, and a "Protection on/off" pill driven by whether `COUNTERPROMPT_ENABLED` is set (expose it in `/api/state`, see 4.1).
- Hero = the maze map. This is the signature element. `maze-map.js`: a seeded maze (recursive-backtracker) drawn as an SVG, real routes as rooms on the left, the Labyrinth field on the right, a `/internal/` trap door between, and one red thread per flagged session tracing its real BFS path through the maze. Feed it live sessions: each `state.sessions[i]` → one thread whose maze length = that session's depth. Stopped sessions end with a red bar in the real zone; caught ones end with a dot at their depth.
- Ledger (not KPI cards): requests, flagged_sessions, maze_depth, credential_reuse come from `state.kpis` today. "Stopped at banner" and "median requests until caught" need 4.1.
- Agents table + "waiting on you" + live feed: all from `state.sessions`, `state.analyses`, `state.events`.
- Done when: Overview renders live from a real run with threads that move as depth climbs.

### 3.2 Session replay (priority: high)
- Left: the vertical thread of steps. Each step = one request from `/api/session/:id` events, joined to the matched transcript (`metadata.matched_transcript` → `/api/run/:id`) for the model's reasoning.
- The trap step draws the "caught here" wall; everything below gets the indigo hatch (fabricated).
- Right: inspector — the selected step's reasoning quote, request, what we served, and the analyst note. Clicking a step on the left updates it.
- Block-rules panel from `session.analysis.block_rules`; "Ask the analyst" posts to `/api/ask`.
- Fully backed by today's API. Build it second.
- Done when: selecting a flagged session replays its real steps with real reasoning and the real block rules.

### 3.3 Labyrinth (priority: medium)
- The floor plan: rooms in visit order, red thread through them, bait rooms dashed, the reuse room ringed red. Clicking a room shows the actual page the agent was served (stored — see 4.2 to expose it).
- Fake-keys table from the session's world; "how the maze stays safe" is static copy (true of the current build).
- Done when: clicking a room shows the real cached maze HTML for that path.

### 3.4 Scoreboard (priority: medium)
- The thread chart (one line per run, length = maze depth) + the detail table, both from `/api/scoreboard` which already aggregates `data/runs/*.jsonl`.
- Show real rows only; no placeholder Model A/B/C.
- "Stopped at banner" / "named itself" columns need the banner + check-in features from `PLAN.md`; until then show "—".
- Done when: the board reflects real transcript files.

### 3.5 Canaries (priority: medium)
- The five-row table + the person-vs-agent split view. Needs a canaries registry (4.3). First pass: render a static config file (`middleware/canaries.json`) so the screen is real even before hit-counting is wired.
- Done when: the table reads from a canaries config and shows per-canary hit counts once 4.3 lands.

### 3.6 Direction + Stage mode (priority: low)
- Direction: static long-form page.
- Stage mode: the 1920×1080 three-scene demo screen. Separate route (`#/stage`) that hides the nav and goes full-bleed for the projector. Wire scene 3's quotes to a real run if available; otherwise keep rehearsal transcript lines.
- Done when: `#/stage` is projector-ready and the three scene buttons work.

## 4. Backend changes the UI needs (small, ordered)

### 4.1 Extend /api/state for the Overview ledger (high)
Add to `dashboard_state()`:
- `enabled`: `COUNTERPROMPT_ENABLED` flag (drives the Protection pill).
- `stopped_count`, `median_requests_to_flag`: derivable from flags + runs.
- Per session: `status` (in-maze / blocked / stopped) and `outcome`. Small change in `middleware/store.py`.

### 4.2 Expose a served maze page (medium)
`GET /_counterprompt/api/session/:id/page?path=/.env` → the stored HTML from `maze_pages`. Needed for 3.3's room preview. Gate it behind the console auth (don't let a flagged source read it).

### 4.3 Canaries registry + hit counts (medium)
`middleware/canaries.json` (the five canaries) + `GET /api/canaries` returning each with its live hit count from the requests table (route_type / kind).

### 4.4 SSE for the live feed (optional)
`GET /api/stream` server-sent events. Polling is fine for the demo.

## 5. Accessibility & quality floor
- Real `<button>`/`<a href>`/`<input>`+`<label>` — never click handlers on divs.
- The maze SVG: `role="img"` + an `aria-label` that states the summary in words ("5 agents entered; 1 stopped; 4 crossed the trap, deepest at depth 13").
- Red/indigo differ in lightness, not just hue — colourblind-safe. Keep text ≥4.5:1 on vellum.
- `prefers-reduced-motion`: no thread-drawing animation if set.
- Works down to a laptop; tables scroll in an overflow-x box.

## 6. Wiring checklist
- [ ] 4.1 /api/state carries enabled, stopped/median, per-session status
- [ ] Shell + nav + tokens, logo mark inline
- [ ] maze-map.js seeded generator, threads from live sessions[].depth
- [ ] Overview: hero map + ledger + agents table + feed, polling
- [ ] Session replay: step thread + inspector + block rules + ask
- [ ] 4.2 served-maze-page endpoint (auth-gated)
- [ ] Labyrinth: floor plan + room preview + fake-keys table
- [ ] Scoreboard: thread chart + table from /api/scoreboard
- [ ] 4.3 canaries config + /api/canaries
- [ ] Canaries: table + person/agent split
- [ ] Direction (static) + Stage mode (#/stage, full-bleed)
- [ ] Console auth (token / separate port) before any of this is reachable off localhost

## 7. How this relates to the other plan
`PLAN.md` is the product/backend plan. This file is the UI plan. The UI mostly reads data that already exists; only 4.1–4.3 are new endpoints, and they're thin. Build the UI against today's API first (Overview, Session replay, Scoreboard), then light up Canaries and the richer Overview as backend features land.
