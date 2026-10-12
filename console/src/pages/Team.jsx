import { useEffect, useState } from "react";
import { api, shortSource } from "../api";

export function Team() {
  const [handoffs, setHandoffs] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    let stop = false;
    async function load() {
      try {
        const next = await api("team");
        if (!stop) setHandoffs(next.handoffs || []);
      } catch (err) {
        if (!stop) setError(err.message);
      }
    }
    load();
    const timer = setInterval(load, 3000);
    return () => {
      stop = true;
      clearInterval(timer);
    };
  }, []);

  return (
    <>
      <h1 className="page-title">Who passed what to whom.</h1>
      <p className="lede">A handoff is recorded when one source requests a path, or uses a credential, that another source was just served. Private agent notes are not part of this record.</p>
      {error ? <p className="empty">{error}</p> : null}
      {handoffs.map((item, index) => (
        <article className="handoff" key={`${item.from}-${item.to}-${item.path}-${index}`}>
          <b title={item.from}>{shortSource(item.from)}</b>
          <span>{item.kind === "credential" ? "Credential" : "Path"} <span className="mono">{item.path}</span> after {item.gap_s}s</span>
          <b title={item.to}>{shortSource(item.to)}</b>
        </article>
      ))}
      {!handoffs.length && !error ? <p className="empty">No handoff yet. It appears when one source requests something another was just served.</p> : null}
    </>
  );
}
