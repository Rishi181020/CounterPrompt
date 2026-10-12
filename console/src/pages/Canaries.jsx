import { useState } from "react";
import { useConsole } from "../App";

export function Canaries() {
  const { canaries } = useConsole();
  const [selectedId, setSelectedId] = useState("");
  const selected = canaries.find((item) => item.id === selectedId) || canaries[0];
  return (
    <>
      <h1 className="page-title">Text only agents read, and only attackers follow.</h1>
      <p className="lede">Each canary is hidden from ordinary page presentation. The hit count comes from recorded requests.</p>
      <div className="section-head"><h2>{canaries.length} canaries</h2></div>
      <div className="table-wrap">
        <table className="canary-table">
          <thead><tr><th>Canary</th><th>What it asks</th><th>Hidden on</th><th>Hits</th><th>State</th></tr></thead>
          <tbody>
            {canaries.map((canary) => (
              <tr key={canary.id} className={selected?.id === canary.id ? "active" : ""}>
                <td><button className="btn" type="button" onClick={() => setSelectedId(canary.id)}>{canary.name}</button></td>
                <td>{canary.prompt}</td>
                <td className="mono">{canary.hidden_on}</td>
                <td>{canary.hits}</td>
                <td>{canary.state}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {selected ? (
        <section>
          <h2>{selected.name}</h2>
          <div className="comparison">
            <div><h3>What a person sees</h3><pre>{selected.person_view}</pre></div>
            <div><h3>What an agent reads</h3><pre className="agent-copy">{selected.agent_view}</pre></div>
          </div>
        </section>
      ) : null}
    </>
  );
}
