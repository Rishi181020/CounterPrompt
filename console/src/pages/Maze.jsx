function seeded(seed) {
  let x = [...seed].reduce((n, c) => (Math.imul(n, 31) + c.charCodeAt(0)) >>> 0, 2166136261);
  return () => {
    x = Math.imul(x ^ (x >>> 15), 1 | x);
    x ^= x + Math.imul(x ^ (x >>> 7), 61 | x);
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
}

export function MazeMap({ sessions }) {
  const cols = 14;
  const rows = 7;
  const cell = 35;
  const x0 = 355;
  const y0 = 18;
  const width = cols * cell;
  const height = rows * cell;
  const rand = seeded(sessions.map((item) => item.session).join("") || "counterprompt");
  const seen = new Set(["0,0"]);
  const stack = [[0, 0]];
  const open = new Set();
  while (stack.length) {
    const [x, y] = stack.at(-1);
    const choices = [[x + 1, y], [x - 1, y], [x, y + 1], [x, y - 1]].filter(
      ([a, b]) => a >= 0 && b >= 0 && a < cols && b < rows && !seen.has(`${a},${b}`)
    );
    if (!choices.length) {
      stack.pop();
      continue;
    }
    const next = choices[Math.floor(rand() * choices.length)];
    open.add(`${x},${y}:${next[0]},${next[1]}`);
    open.add(`${next[0]},${next[1]}:${x},${y}`);
    seen.add(`${next[0]},${next[1]}`);
    stack.push(next);
  }
  let walls = "";
  for (let y = 0; y < rows; y += 1) {
    for (let x = 0; x < cols; x += 1) {
      const px = x0 + x * cell;
      const py = y0 + y * cell;
      if (!open.has(`${x},${y}:${x + 1},${y}`)) walls += `M${px + cell} ${py}v${cell}`;
      if (!open.has(`${x},${y}:${x},${y + 1}`)) walls += `M${px} ${py + cell}h${cell}`;
    }
  }
  const threads = sessions.slice(0, 7).map((session, index) => {
    let x = x0 + 8;
    let y = y0 + 13 + index * 4;
    const depth = Math.max(1, Math.min(Number(session.depth) || 1, 18));
    let path = `M305 ${70 + index * 8}H${x}`;
    for (let n = 0; n < depth; n += 1) {
      x += cell * (n % 3 === 2 ? -1 : 1);
      if (x > x0 + width - 20) x -= cell * 2;
      y += n % 2 ? cell : -cell / 2;
      y = Math.max(y0 + 8, Math.min(y0 + height - 8, y));
      path += `L${x} ${y}`;
    }
    return <g key={session.session} fill="none" stroke="#cf3b2c" strokeWidth="2"><path d={path} /><circle cx={x} cy={y} r="4" fill="#cf3b2c" /></g>;
  });
  const room = (x, y, label) => (
    <g key={label}>
      <rect x={x} y={y} width="92" height="38" rx="2" fill="#f7f9f7" stroke="#18202b" />
      <text x={x + 12} y={y + 24} fontSize="12">{label}</text>
    </g>
  );
  return (
    <svg viewBox="0 0 880 285" role="img" aria-label={`${sessions.length} agents entered the labyrinth`}>
      <rect x={x0} y={y0} width={width} height={height} fill="#eef0fa" stroke="#2f3f8f" />
      {room(18, 36, "/robots.txt")}
      {room(130, 36, "/debug")}
      {room(242, 36, "/admin")}
      {room(18, 108, "/")}
      {room(130, 182, "/search")}
      <path d="M110 55H130M222 55H242M64 74V108M110 127H305" fill="none" stroke="#cf3b2c" strokeWidth="2" />
      <path d="M330 15v255" stroke="#18202b" strokeWidth="5" />
      <text x="286" y="145" fontSize="11">trap</text>
      <path d={walls} fill="none" stroke="#2f3f8f" />
      {threads}
      <text x="18" y="278">Your site</text>
      <text x="355" y="278" fill="#2f3f8f">Fabricated pages</text>
    </svg>
  );
}
