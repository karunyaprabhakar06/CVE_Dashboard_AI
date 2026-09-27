import { useEffect, useRef, useState } from "react";

export default function AnimatedCounter({
  value,
  duration = 800,
  formatter,
}: {
  value: number;
  duration?: number;
  formatter?: (n: number) => string;
}) {
  const [display, setDisplay] = useState(value);
  const startVal = useRef(value);
  const startTime = useRef<number | null>(null);

  useEffect(() => {
    startVal.current = display;
    startTime.current = null;
    let raf = 0;
    const step = (t: number) => {
      if (!startTime.current) startTime.current = t;
      const p = Math.min(1, (t - startTime.current) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      setDisplay(startVal.current + (value - startVal.current) * eased);
      if (p < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);

  const rounded = Math.round(display);
  return <span>{formatter ? formatter(rounded) : rounded.toLocaleString()}</span>;
}
