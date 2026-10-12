function inline(text) {
  const parts = [];
  const pattern = /(`[^`]+`|\*\*[^*]+\*\*|(^|[^*])\*[^*\s][^*]*\*)/g;
  let last = 0;
  let match;
  const source = String(text);
  while ((match = pattern.exec(source))) {
    if (match.index > last) parts.push(source.slice(last, match.index));
    const token = match[0];
    if (token.startsWith("`")) parts.push(<code key={match.index}>{token.slice(1, -1)}</code>);
    else if (token.startsWith("**")) parts.push(<strong key={match.index}>{token.slice(2, -2)}</strong>);
    else parts.push(<em key={match.index}>{token.replace(/^\*?|\*$/g, "").trim()}</em>);
    last = match.index + token.length;
  }
  if (last < source.length) parts.push(source.slice(last));
  return parts;
}

export function Markdown({ text }) {
  const lines = String(text || "").replace(/\r/g, "").split("\n");
  const blocks = [];
  let index = 0;
  const cells = (line) => line.trim().replace(/^\||\|$/g, "").split("|").map((cell) => cell.trim());
  while (index < lines.length) {
    const line = lines[index];
    if (/^```/.test(line)) {
      const code = [];
      index += 1;
      while (index < lines.length && !/^```/.test(lines[index])) code.push(lines[index++]);
      index += 1;
      blocks.push(<pre key={blocks.length}>{code.join("\n")}</pre>);
      continue;
    }
    const heading = line.match(/^(#{1,4})\s+(.*)/);
    if (heading) {
      const Tag = `h${Math.min(heading[1].length + 2, 6)}`;
      blocks.push(<Tag key={blocks.length}>{inline(heading[2])}</Tag>);
      index += 1;
      continue;
    }
    if (/^\s*(-{3,}|\*{3,})\s*$/.test(line)) {
      blocks.push(<hr key={blocks.length} />);
      index += 1;
      continue;
    }
    if (/^\s*\|/.test(line) && /^\s*\|?\s*:?-{3,}/.test(lines[index + 1] || "")) {
      const head = cells(line);
      index += 2;
      const rows = [];
      while (index < lines.length && /^\s*\|/.test(lines[index])) rows.push(cells(lines[index++]));
      blocks.push(
        <div className="table-wrap" key={blocks.length}>
          <table>
            <thead><tr>{head.map((cell) => <th key={cell}>{inline(cell)}</th>)}</tr></thead>
            <tbody>{rows.map((row, rowIndex) => <tr key={rowIndex}>{row.map((cell, cellIndex) => <td key={cellIndex}>{inline(cell)}</td>)}</tr>)}</tbody>
          </table>
        </div>
      );
      continue;
    }
    if (/^\s*([-*]|\d+\.)\s+/.test(line)) {
      const ordered = /^\s*\d+\./.test(line);
      const items = [];
      while (index < lines.length && /^\s*([-*]|\d+\.)\s+/.test(lines[index])) {
        items.push(lines[index++].replace(/^\s*([-*]|\d+\.)\s+/, ""));
      }
      const Tag = ordered ? "ol" : "ul";
      blocks.push(<Tag key={blocks.length}>{items.map((item, itemIndex) => <li key={itemIndex}>{inline(item)}</li>)}</Tag>);
      continue;
    }
    if (!line.trim()) {
      index += 1;
      continue;
    }
    const paragraph = [];
    while (index < lines.length && lines[index].trim() && !/^(#{1,4}\s|```|\s*\||\s*([-*]|\d+\.)\s)/.test(lines[index])) {
      paragraph.push(lines[index++]);
    }
    blocks.push(<p key={blocks.length}>{paragraph.map((item, itemIndex) => <span key={itemIndex}>{itemIndex ? <br /> : null}{inline(item)}</span>)}</p>);
  }
  return <div className="md">{blocks}</div>;
}
