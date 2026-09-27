export default function GridOverlay() {
  return (
    <div className="fixed inset-0 pointer-events-none">
      <div className="absolute inset-0 grid-bg opacity-[0.35] animate-gridMove" />
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-bg/80" />
      {/* floating particles */}
      <div className="absolute inset-0 overflow-hidden">
        {Array.from({ length: 18 }).map((_, i) => (
          <span
            key={i}
            className="absolute rounded-full bg-cyber-cyan/40 blur-[1px]"
            style={{
              width: 2 + (i % 3),
              height: 2 + (i % 3),
              left: `${(i * 53) % 100}%`,
              top: `${(i * 37) % 100}%`,
              animation: `float ${6 + (i % 5)}s ease-in-out ${i * 0.3}s infinite`,
              opacity: 0.4,
            }}
          />
        ))}
      </div>
    </div>
  );
}
