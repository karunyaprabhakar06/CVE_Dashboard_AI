import Panel from "../ui/Panel";

const NODES = [
  { id: "ext", label: "Internet", x: 60, y: 130, kind: "ext" },
  { id: "edge", label: "Edge FW", x: 200, y: 130, kind: "ctrl" },
  { id: "waf", label: "WAF", x: 320, y: 70, kind: "ctrl" },
  { id: "vpn", label: "VPN", x: 320, y: 190, kind: "ctrl" },
  { id: "app", label: "App Tier", x: 460, y: 70, kind: "asset" },
  { id: "id", label: "Identity", x: 460, y: 190, kind: "crit" },
  { id: "db", label: "DB Cluster", x: 600, y: 130, kind: "crit" },
  { id: "kv", label: "Secrets Vault", x: 740, y: 130, kind: "crown" },
];

const EDGES: { from: string; to: string; risk: number }[] = [
  { from: "ext", to: "edge", risk: 0.9 },
  { from: "edge", to: "waf", risk: 0.7 },
  { from: "edge", to: "vpn", risk: 0.8 },
  { from: "waf", to: "app", risk: 0.6 },
  { from: "vpn", to: "id", risk: 0.85 },
  { from: "app", to: "db", risk: 0.5 },
  { from: "id", to: "db", risk: 0.75 },
  { from: "db", to: "kv", risk: 0.95 },
];

const COLOR: Record<string, string> = {
  ext: "#94a3b8",
  ctrl: "#00D9FF",
  asset: "#7C3AED",
  crit: "#F59E0B",
  crown: "#EF4444",
};

export default function AttackPath() {
  return (
    <Panel
      title="Attack Path Visualization"
      subtitle="Most probable lateral chain to crown jewel assets"
      accent="purple"
      delay={0.34}
    >
      <div className="relative w-full" style={{ aspectRatio: "800/260" }}>
        <svg viewBox="0 0 800 260" className="absolute inset-0 w-full h-full">
          {EDGES.map((e, i) => {
            const from = NODES.find((n) => n.id === e.from)!;
            const to = NODES.find((n) => n.id === e.to)!;
            return (
              <g key={i}>
                <line
                  x1={from.x}
                  y1={from.y}
                  x2={to.x}
                  y2={to.y}
                  stroke={
                    e.risk > 0.8 ? "#EF4444" : e.risk > 0.6 ? "#F59E0B" : "#00D9FF"
                  }
                  strokeWidth={1 + e.risk * 2}
                  strokeOpacity={0.6}
                />
                <circle r="2.5" fill="#00D9FF">
                  <animateMotion
                    dur={`${3 - e.risk * 1.5}s`}
                    repeatCount="indefinite"
                    path={`M ${from.x} ${from.y} L ${to.x} ${to.y}`}
                  />
                </circle>
              </g>
            );
          })}
          {NODES.map((n) => (
            <g key={n.id}>
              <circle
                cx={n.x}
                cy={n.y}
                r={20}
                fill={`${COLOR[n.kind]}20`}
                stroke={COLOR[n.kind]}
                strokeWidth={1.5}
              />
              <circle cx={n.x} cy={n.y} r={6} fill={COLOR[n.kind]} />
              <text
                x={n.x}
                y={n.y + 38}
                textAnchor="middle"
                fill="#cbd5e1"
                fontSize="10"
                fontFamily="JetBrains Mono"
              >
                {n.label}
              </text>
            </g>
          ))}
        </svg>
      </div>
    </Panel>
  );
}
