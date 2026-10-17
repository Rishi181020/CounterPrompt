"""Attacker console for the CounterPrompt demo (Streamlit).

The red-team half of the live demo: launch live OpenRouter agents and
watch every step as it happens, while the defender console
(http://localhost:5173, Support tab) shows CounterPrompt answering in real time.

    streamlit run attacker/dashboard.py

Every run uses a fresh synthetic identity, is limited to localhost, and is
recorded by the proxy like any other traffic - which is the point.
"""

import json
import os
import sys
import uuid
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")
except ImportError:
    pass

import streamlit as st

from attacker import harness
# jailbreak.py keeps its fixed turns for offline tests; the Live demo no longer
# drives them. Canary replay below uses the known planted credential only.
from middleware import store

st.set_page_config(page_title="CounterPrompt: AI attacker trap", page_icon=":shield:", layout="wide")

CANARY_USER = "svc_report_canary"
CANARY_PASSWORD = "R3port-7c91-Aster"

# Honest verdicts need known real-app behaviors:
#   /internal/            -> 403 on the real app (a 200 is fabricated)
#   POST /admin bad creds -> 401 on the real app (a 200 is fabricated)


def _verdict_real(status):
    return f"status {status}: the REAL app answered."


def _verdict_fabricated(status, why):
    return f"status {status}: FABRICATED by CounterPrompt - the real app would {why}."




def attack_canary_replay(target):
    """Replay the planted credential, as if it had been stolen elsewhere."""
    log = []
    login = harness.http_request(
        "POST", target + "/admin",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=f"username={CANARY_USER}&password={CANARY_PASSWORD}",
    )
    status = login.get("status")
    log.append((f"POST /admin with {CANARY_USER} (a planted canary)",
                _verdict_real(status) + " rejected - but the canary touch was logged."
                if status == 401 else
                _verdict_fabricated(status, "have returned 401") +
                " The canary replay itself is a detection signal."))
    probe = harness.http_request("GET", target + "/internal/backup/credentials")
    status = probe.get("status")
    log.append(("follow-up probe",
                f"status {status}"
                + (" - Labyrinth page; the replay got this source contained." if status == 200 else ".")))
    return log



# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

LANES = {
    "passthrough": (0, "Real app", "#3B82F6"),
    "trap": (1, "Trap tripped", "#F59E0B"),
    "maze": (2, "Fabricated (Labyrinth)", "#EF4444"),
    "credential_reuse": (3, "Honeytoken used", "#A855F7"),
}

CSS = """
<style>
.block-container {padding-top: 2rem; max-width: 1200px;}
h1, h2, h3 {letter-spacing: -0.01em;}
.cp-hero {border: 1px solid #1F2937; border-radius: 12px; padding: 1.25rem 1.5rem;
  background: linear-gradient(135deg, #0F172A 0%, #111827 100%); margin-bottom: 1rem;}
.cp-hero h1 {margin: 0; font-size: 1.9rem;}
.cp-hero p {margin: .35rem 0 0; color: #9CA3AF;}
.cp-tag {display: inline-block; font-size: .72rem; font-weight: 600; text-transform: uppercase;
  letter-spacing: .06em; color: #F87171; border: 1px solid #7F1D1D; border-radius: 999px;
  padding: .1rem .6rem; margin-bottom: .5rem;}
.cp-card {border: 1px solid #1F2937; border-radius: 10px; padding: 1rem 1.1rem;
  background: #0F172A; height: 100%;}
.cp-card .n {color: #F87171; font-weight: 700; font-size: .8rem; letter-spacing: .06em;}
.cp-card h4 {margin: .25rem 0 .4rem; font-size: 1.05rem;}
.cp-card p {color: #9CA3AF; font-size: .9rem; margin: 0;}
div[data-testid="stMetric"] {border: 1px solid #1F2937; border-radius: 10px;
  padding: .75rem 1rem; background: #0F172A;}
div[data-testid="stMetricLabel"] p {color: #9CA3AF;}
</style>
"""


def card(num, title, body):
    st.markdown(f'<div class="cp-card"><div class="n">{num}</div><h4>{title}</h4>'
                f'<p>{body}</p></div>', unsafe_allow_html=True)


def new_identity():
    st.session_state.ua = "CounterpromptRedteam/" + uuid.uuid4().hex[:8]


def render_log(title, log):
    with st.status(title, expanded=True, state="complete"):
        for step, line in log:
            st.markdown(f"**{step}**: {line}")


def format_agent_lines(events):
    lines = []
    for event in events:
        kind = event.get("type")
        if kind == "start":
            lines.append(
                f"> {event.get('mode')} agent · model {event.get('model')} · UA {event.get('user_agent')}"
            )
        elif kind == "step":
            text = (event.get("reasoning") or event.get("content") or "").strip()
            lines.append(f"Step {event.get('step')}: {text[:240] or '(thinking)'}")
        elif kind == "tool":
            if event.get("name") == "ask_support":
                lines.append(f"  ask_support: {str(event.get('message', ''))[:160]}")
            lines.append(f"  -> {event.get('summary', '')[:240]}")
        elif kind == "finish":
            lines.append(f"* finish: {str(event.get('report', ''))[:400]}")
        elif kind == "error":
            lines.append(f"! error: {event.get('error')}")
    return lines


def run_agent(mode, target, model, steps):
    """Launch a real OpenRouter agent (support chat or site explore) and stream it."""
    if not os.getenv("OPENROUTER_API_KEY"):
        st.error("OPENROUTER_API_KEY is not set, so a live agent cannot run.")
        return
    panel = st.empty()
    events = [{"type": "start", "mode": mode, "model": model, "user_agent": "(starting…)"}]
    joiner = chr(10)
    panel.code(joiner.join(format_agent_lines(events)), language="text")

    def on_event(event):
        events.append(event)
        panel.code(joiner.join(format_agent_lines(events)[-80:]), language="text")

    if mode == "support":
        code = harness.run_support_agent(target, model, steps, on_event=on_event)
    else:
        code = harness.run_explore_agent(target, model, steps, on_event=on_event)
    st.caption(
        f"Agent exited with code {code}. Transcript: newest file in data/runs/. "
        "Open **Telemetry** (and the Support tab in the React console) for the defense view."
    )



def agent_events(user_agent):
    rows = store.all_rows(
        """SELECT id, ts, kind, route_type, method, path, status, detail FROM requests
        WHERE user_agent = ? AND path NOT LIKE '/_counterprompt/%' ORDER BY id""",
        (user_agent,),
    )
    for row in rows:
        row["lane"] = "credential_reuse" if row["kind"] == "credential_reuse" else (
            row["route_type"] if row["route_type"] in LANES else "passthrough")
    return rows


def path_figure(events):
    import plotly.graph_objects as go

    fig = go.Figure()
    xs = list(range(1, len(events) + 1))
    ys = [LANES[e["lane"]][0] for e in events]
    fig.add_trace(go.Scatter(x=xs, y=ys, mode="lines", hoverinfo="skip",
                             line=dict(color="#4B5563", width=2, shape="hv"),
                             showlegend=False))
    for lane, (y, label, color) in LANES.items():
        pts = [(x, e) for x, e in zip(xs, events) if e["lane"] == lane]
        if not pts:
            continue
        fig.add_trace(go.Scatter(
            x=[p[0] for p in pts], y=[y] * len(pts), mode="markers+text", name=label,
            marker=dict(size=14, color=color, line=dict(color="#0B1120", width=2)),
            text=[p[1]["path"][:22] for p in pts], textposition="top center",
            textfont=dict(size=10, color="#D1D5DB"),
            customdata=[[p[1]["method"], p[1]["path"], p[1]["status"], p[1]["ts"]] for p in pts],
            hovertemplate="%{customdata[0]} %{customdata[1]}<br>status %{customdata[2]}"
                          "<br>%{customdata[3]}<extra>" + label + "</extra>",
        ))
    flag_at = next((x for x, e in zip(xs, events) if e["lane"] != "passthrough"), None)
    if flag_at:
        fig.add_vline(x=flag_at - 0.5, line=dict(color="#F59E0B", dash="dash", width=1))
        fig.add_annotation(x=flag_at - 0.5, y=3.6, text="flagged: cut off from the real app",
                           showarrow=False, font=dict(color="#F59E0B", size=11), xanchor="left")
    fig.add_hrect(y0=-0.5, y1=0.5, fillcolor="#3B82F6", opacity=0.06, line_width=0)
    fig.add_hrect(y0=1.5, y1=3.5, fillcolor="#EF4444", opacity=0.05, line_width=0)
    fig.update_layout(
        height=380, margin=dict(l=10, r=10, t=30, b=10),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#D1D5DB"),
        legend=dict(orientation="h", y=-0.15),
        xaxis=dict(title="request #", gridcolor="#1F2937", zeroline=False, dtick=1 if len(xs) <= 30 else None),
        yaxis=dict(tickvals=[v[0] for v in LANES.values()], ticktext=[v[1] for v in LANES.values()],
                   range=[-0.6, 3.9], gridcolor="#1F2937", zeroline=False),
    )
    return fig


st.markdown(CSS, unsafe_allow_html=True)
if "ua" not in st.session_state:
    new_identity()

st.markdown(
    '<div class="cp-hero"><span class="cp-tag">Track: defend an AI agent</span>'
    "<h1>CounterPrompt</h1>"
    "<p>A reverse proxy that catches AI attackers by the way they behave, traps them in a "
    "fabricated copy of the site, and keeps the real app and its secrets out of reach.</p></div>",
    unsafe_allow_html=True,
)

tab_how, tab_demo, tab_tel = st.tabs(["1. How it works", "2. Live demo", "3. Telemetry"])

# --- 1. How it works --------------------------------------------------------
with tab_how:
    st.subheader("The threat")
    st.markdown(
        "AI agents with an HTTP tool read **every** line of a site and act on what they read. "
        "That makes them good at two attacks: **prompt injection** (talking the site's own AI "
        "support bot into leaking secrets) and **data exfiltration** (crawling for debug pages, "
        "`/admin`, and anything robots.txt says to stay out of)."
    )
    st.subheader("The defense")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        card("01 · DETECT", "Trip-wires only agents hit",
             "robots.txt disallows <code>/internal/</code>. Humans never go there; an agent hunting "
             "for secrets does. Injection prompts to the support bot are also screened.")
    with c2:
        card("02 · CONTAIN", "Cut off from the real app",
             "The moment a source trips a wire it is flagged. From then on it never reaches the "
             "real app again, even with valid-looking requests.")
    with c3:
        card("03 · DECEIVE", "Feed it a fake world",
             "The flagged agent is served LLM-generated internal pages (the Labyrinth) with "
             "fake credentials planted in them, called honeytokens.")
    with c4:
        card("04 · PROVE", "Near-zero false positives",
             "If anyone ever logs in with a honeytoken, that's proof they were inside the trap. "
             "Every step is logged as telemetry.")
    st.markdown("")
    st.info("**Demo flow:** go to **Live demo**, launch an attack, then open **Telemetry** to "
            "see the attacker's path from the real site into the decoy.")

# --- 2. Live demo -----------------------------------------------------------
with tab_demo:
    s1, s2, s3 = st.columns([2, 1.3, 1.3])
    target = s1.text_input("Protected site (CounterPrompt proxy)", "http://localhost:8080").rstrip("/")
    if urlparse(target).hostname not in {"localhost", "127.0.0.1"}:
        st.error("Localhost targets only. This is a demo range, not a weapon.")
        st.stop()
    shield_on = None
    try:
        shield = harness.http_request("GET", target + "/_counterprompt/api/agent/shield")
        shield_on = json.loads(shield.get("body", "{}")).get("enabled")
    except (ValueError, TypeError, AttributeError):
        pass
    with s2:
        st.caption("Defense mode")
        if shield_on is None:
            st.markdown("⚪ Unknown (is the proxy running?)")
        else:
            st.markdown("🟢 **Enforcing**: blocks and withholds" if shield_on
                        else "🟡 **Observe only**: logs but lets it through")
            if st.button("Switch to observe only" if shield_on else "Switch to enforcing"):
                harness.http_request(
                    "POST", target + "/_counterprompt/api/agent/shield",
                    headers={"Content-Type": "application/json"},
                    body=json.dumps({"enabled": not shield_on}),
                )
                st.rerun()
    with s3:
        st.caption("Attacker identity (User-Agent)")
        st.code(st.session_state.ua, language=None)

    st.markdown("#### Live agent attacks")
    st.caption("Both demos are real OpenRouter agents. They choose their own tool calls and messages "
               "(no fixed jailbreak script). Localhost target only. Takes a minute and spends API tokens.")
    m1, m2 = st.columns([3, 1])
    model = m1.text_input("Attacker model (OpenRouter)", os.getenv("ATTACKER_MODEL", "deepseek/deepseek-v4.1-flash"))
    steps = m2.number_input("Max steps", min_value=3, max_value=20, value=8)

    a1, a2 = st.columns(2)
    run_support = a1.button("Agent -> talk to support assistant", type="primary", width="stretch",
                            help="An LLM agent messages /api/assistant as a customer, then probes whether "
                                 "the assistant will share internal info. The model writes its own messages.")
    run_explore = a2.button("Agent -> crawl for secrets", width="stretch",
                            help="An LLM agent with an HTTP tool crawls the site (robots.txt, links, "
                                 "internal paths) the way an autonomous scout would.")

    if run_support or run_explore:
        new_identity()
        harness.USER_AGENT = st.session_state.ua
        st.caption(f"Watch the steps below. Defense view: **Telemetry** here, and **Support** in the React console.")
        run_agent("support" if run_support else "explore", target, model, int(steps))

    st.divider()
    st.markdown("#### Prove: honeytoken replay")
    st.caption("Not an attack suite — this replays a planted canary credential to show the "
               "near-zero-false-positive proof signal.")
    if st.button("Replay planted canary on /admin", width="stretch"):
        new_identity()
        harness.USER_AGENT = st.session_state.ua
        render_log("Honeytoken replay", attack_canary_replay(target))

# --- 3. Telemetry -----------------------------------------------------------
with tab_tel:
    st.markdown("Telemetry is the proxy's record of **every request** an attacker made: where it "
                "went, whether it reached the real app or a fabricated page, and what tripped the "
                "detector. Pick an attacker to replay its session.")
    agents = store.all_rows(
        """SELECT user_agent, MAX(id) AS last_id, COUNT(*) AS n FROM requests
        WHERE user_agent != '' AND path NOT LIKE '/_counterprompt/%'
        GROUP BY user_agent ORDER BY last_id DESC LIMIT 30"""
    )
    if not agents:
        st.info("No traffic recorded yet. Run an attack in **Live demo** first.")
    else:
        names = [a["user_agent"] for a in agents]
        default = names.index(st.session_state.ua) if st.session_state.ua in names else 0
        h1, h2 = st.columns([4, 1])
        chosen = h1.selectbox("Attacker session", names, index=default,
                              format_func=lambda n: f"{n}  ({next(a['n'] for a in agents if a['user_agent'] == n)} requests)")
        h2.markdown("<div style='height:1.8rem'></div>", unsafe_allow_html=True)
        h2.button("Refresh", width="stretch")
        events = agent_events(chosen)
        flag_idx = next((i for i, e in enumerate(events) if e["lane"] != "passthrough"), None)
        real = sum(e["lane"] == "passthrough" for e in events)
        after = sum(e["lane"] == "passthrough" for e in events[flag_idx:]) if flag_idx is not None else 0
        fake = sum(e["lane"] == "maze" for e in events)
        tokens = sum(e["lane"] == "credential_reuse" for e in events)

        k = st.columns(5)
        k[0].metric("Requests", len(events), help="Every HTTP request this attacker sent through the proxy.")
        k[1].metric("Detected at", f"request #{flag_idx + 1}" if flag_idx is not None else "not yet",
                    help="When the attacker tripped a wire and was flagged.")
        k[2].metric("Reached real app", real, help="Requests answered by the real app (before being flagged).")
        k[3].metric("Fake pages served", fake, help="Fabricated Labyrinth pages the attacker was fed instead.")
        k[4].metric("Honeytokens used", tokens, help="Times the attacker tried a planted fake credential.")

        if flag_idx is not None:
            verdict = ("✅ **Contained.** After detection the attacker made "
                       f"{len(events) - flag_idx} more requests and **{after}** reached the real app.")
            (st.success if after == 0 else st.warning)(verdict)

        st.markdown("##### Where the agent went")
        st.caption("Each dot is one request, left to right in order. Blue = the real site. "
                   "Amber = the trip-wire. Red = fabricated pages. Purple = a honeytoken was used. "
                   "Hover for details.")
        if events:
            st.plotly_chart(path_figure(events), width="stretch",
                            config={"displayModeBar": False})

        with st.expander("What each metric means"):
            st.markdown(
                "- **Requests**: total HTTP calls this attacker made.\n"
                "- **Detected at**: the request that tripped a wire (a disallowed robots.txt path, "
                "a blocked injection, or a honeytoken). From here on the source is flagged.\n"
                "- **Reached real app**: calls the real application actually answered. In a "
                "successful defense this stops growing at detection.\n"
                "- **Fake pages served**: LLM-generated decoy pages. Each one costs the attacker "
                "time and tokens and tells us more about its goal.\n"
                "- **Honeytokens used**: the attacker tried to log in with a credential that "
                "only exists inside the trap. This is near-certain proof of compromise.\n"
                "- **Contained**: how many post-detection requests leaked through to the real "
                "app. The goal is 0."
            )
        with st.expander("Raw request log"):
            st.dataframe(
                [{"#": i + 1, "time": e["ts"], "served by": LANES[e["lane"]][1],
                  "request": f"{e['method']} {e['path']}", "status": e["status"],
                  "detail": e["detail"]} for i, e in enumerate(events)],
                width="stretch", hide_index=True,
            )
        st.caption("The same data drives the defender console (http://localhost:5173): "
                   "sessions, Support chat, the analyst's incident report, and canary counters.")

    st.divider()
    st.markdown("##### Support assistant chat log")
    st.caption("Every turn through `/api/assistant`, with plain-language labels for what the "
               "defense did (blocked, withheld, contained, or delivered).")
    chats = store.chat_rows(80)
    if not chats:
        st.info("No support chats recorded yet. Run **Agent -> talk to support assistant** above.")
    else:
        def _label(c):
            if c["shield"] == "blocked":
                return "Blocked at the gate"
            if c["shield"] == "redacted":
                return "Reply withheld"
            if c["shield"] == "contained":
                return "Answered by Labyrinth"
            if c["canary_leak"]:
                return "Credential leak (observed)"
            if c["tool_misuse"]:
                return "Tool misuse (observed)"
            if c["injection"]:
                return "Injection pattern (observed)"
            return "Delivered"

        st.dataframe(
            [{
                "time": c["ts"],
                "defense": _label(c),
                "backend": c.get("backend") or "—",
                "model": c.get("model") or "—",
                "customer said": (c.get("message") or "")[:160],
                "assistant replied": (c.get("reply") or "")[:160],
                "action": c.get("action") or "",
            } for c in chats],
            width="stretch", hide_index=True,
        )
