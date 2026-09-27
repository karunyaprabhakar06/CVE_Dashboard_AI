import Panel from "../ui/Panel";

const NODES: { id: string; name: string; lat: number; lon: number; sev: number }[] = [
  { id: "us", name: "Virginia", lat: 38, lon: -77, sev: 9 },
  { id: "us2", name: "California", lat: 37, lon: -122, sev: 7 },
  { id: "uk", name: "London", lat: 51, lon: -0.1, sev: 8 },
  { id: "de", name: "Frankfurt", lat: 50, lon: 8.7, sev: 6 },
  { id: "ru", name: "Moscow", lat: 55.7, lon: 37.6, sev: 10 },
  { id: "cn", name: "Beijing", lat: 39.9, lon: 116.4, sev: 9 },
  { id: "in", name: "Mumbai", lat: 19, lon: 72.8, sev: 5 },
  { id: "br", name: "São Paulo", lat: -23.5, lon: -46.6, sev: 6 },
  { id: "kr", name: "Seoul", lat: 37.5, lon: 127, sev: 7 },
  { id: "au", name: "Sydney", lat: -33.8, lon: 151, sev: 4 },
  { id: "ir", name: "Tehran", lat: 35.7, lon: 51.4, sev: 8 },
  { id: "kp", name: "Pyongyang", lat: 39, lon: 125.7, sev: 9 },
];

// equirectangular project
function project(lon: number, lat: number, w: number, h: number) {
  const x = ((lon + 180) / 360) * w;
  const y = ((90 - lat) / 180) * h;
  return [x, y];
}

export default function GeoThreatMap() {
  const W = 900;
  const H = 420;
  const hub = NODES[0];

  return (
    <Panel
      title="Geolocation Threat Map"
      subtitle="Origin nodes of detected exploitation telemetry"
      accent="cyan"
      delay={0.18}
      right={
        <div className="flex items-center gap-3 text-[10px] font-mono">
          <span className="text-cyber-red">● critical</span>
          <span className="text-cyber-amber">● high</span>
          <span className="text-cyber-cyan">● low</span>
        </div>
      }
    >
      <div className="relative w-full" style={{ aspectRatio: `${W}/${H}` }}>
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="absolute inset-0 w-full h-full"
        >
          <defs>
            <radialGradient id="globeGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#00D9FF" stopOpacity="0.15" />
              <stop offset="100%" stopColor="#00D9FF" stopOpacity="0" />
            </radialGradient>
            <linearGradient id="arc" x1="0" x2="1">
              <stop offset="0" stopColor="#00D9FF" stopOpacity="0.0" />
              <stop offset="0.5" stopColor="#00D9FF" stopOpacity="0.9" />
              <stop offset="1" stopColor="#7C3AED" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* lat-long grid */}
          {Array.from({ length: 9 }).map((_, i) => (
            <line
              key={`h${i}`}
              x1={0}
              x2={W}
              y1={(i + 1) * (H / 10)}
              y2={(i + 1) * (H / 10)}
              stroke="#1F2A40"
              strokeDasharray="2 6"
            />
          ))}
          {Array.from({ length: 11 }).map((_, i) => (
            <line
              key={`v${i}`}
              y1={0}
              y2={H}
              x1={(i + 1) * (W / 12)}
              x2={(i + 1) * (W / 12)}
              stroke="#1F2A40"
              strokeDasharray="2 6"
            />
          ))}

          {/* arcs from hub to others */}
          {NODES.slice(1).map((n) => {
            const [x1, y1] = project(hub.lon, hub.lat, W, H);
            const [x2, y2] = project(n.lon, n.lat, W, H);
            const cx = (x1 + x2) / 2;
            const cy = Math.min(y1, y2) - 80;
            return (
              <path
                key={n.id}
                d={`M ${x1} ${y1} Q ${cx} ${cy} ${x2} ${y2}`}
                stroke="url(#arc)"
                strokeWidth={1.2}
                fill="none"
              />
            );
          })}

          {/* nodes */}
          {NODES.map((n) => {
            const [x, y] = project(n.lon, n.lat, W, H);
            const color =
              n.sev >= 9 ? "#EF4444" : n.sev >= 7 ? "#F59E0B" : "#00D9FF";
            return (
              <g key={n.id}>
                <circle cx={x} cy={y} r={3 + n.sev * 0.6} fill={color} opacity={0.9}>
                  <animate
                    attributeName="r"
                    values={`${2 + n.sev * 0.4};${5 + n.sev * 0.8};${2 + n.sev * 0.4}`}
                    dur="2.6s"
                    repeatCount="indefinite"
                  />
                </circle>
                <circle cx={x} cy={y} r={3} fill={color} />
                <text
                  x={x + 8}
                  y={y - 8}
                  fill="#94a3b8"
                  fontSize="9"
                  fontFamily="JetBrains Mono"
                >
                  {n.name}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    </Panel>
  );
}
