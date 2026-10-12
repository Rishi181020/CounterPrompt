import { Link } from "react-router-dom";
import { formatTime } from "../api";
import { useConsole } from "../App";
import { MazeMap } from "./Maze";

export function Overview() {
  const { state } = useConsole();
  if (!state) return <p className="empty">Loading the console.</p>;
  const sessions = state.sessions || [];
  const events = state.events || [];
  const kpis = state.kpis || {};
  return (
    <>
      <h1 className="page-title">
        {sessions.length
          ? `${sessions.length} agent${sessions.length === 1 ? "" : "s"} caught. None reached a real page after the catch.`
          : "No agents caught yet."}
      </h1>
      <p className="lede">
        {sessions.length
          ? "Caught sources are served isolated, fabricated pages. The requests stay visible here."
          : "The console is listening for trap and canary signals."}
      </p>
      <div className="ledger">
        <div className="metric"><small>agent sessions</small><strong>{kpis.flagged_sessions || 0}</strong></div>
        <div className="metric"><small>median requests until caught</small><strong>{state.median_requests_to_flag ?? "—"}</strong></div>
        <div className="metric"><small>stopped at the banner</small><strong>{state.stopped_count || 0}</strong></div>
        <div className="metric"><small>requests observed</small><strong>{kpis.requests || 0}</strong></div>
        <div className="metric"><small>real pages after a catch</small><strong>0</strong></div>
      </div>
      <section className="panel overview-map">
        <h2>Where the agents went</h2>
        <MazeMap sessions={sessions} />
      </section>
      <div className="grid">
        <section>
          <div className="section-head"><h2>Agents</h2><Link to="/sessions">Open a replay</Link></div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Session</th><th>Caught by</th><th>Depth</th><th>Now</th></tr></thead>
              <tbody>
                {sessions.length ? sessions.map((item) => (
                  <tr key={item.session}>
                    <td><Link className="mono" to={`/sessions/${item.session}`}>{item.session}</Link></td>
                    <td>{item.reason}</td>
                    <td>{item.depth || 0}</td>
                    <td>{item.status}</td>
                  </tr>
                )) : <tr><td className="empty" colSpan="4">No flagged sessions.</td></tr>}
              </tbody>
            </table>
          </div>
        </section>
        <aside>
          <div className="section-head"><h2>Latest</h2></div>
          <ul className="feed">
            {events.slice(0, 7).map((event) => (
              <li key={event.id || event.ts + event.path}>
                <time>{formatTime(event.ts)}</time>
                <span className="mono">{event.method} {event.normalized_path || event.path}</span>
              </li>
            ))}
            {!events.length && <li className="empty">Waiting for traffic.</li>}
          </ul>
        </aside>
      </div>
    </>
  );
}
