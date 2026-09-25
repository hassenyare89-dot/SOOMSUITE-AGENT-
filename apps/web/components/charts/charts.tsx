"use client";

/**
 * Minimal SVG charts following the platform data-viz rules:
 * one axis, hairline recessive grid, thin marks with 4px rounded data-ends, 2px surface gaps
 * between stacked segments, fixed categorical slot order (identity follows the entity),
 * legend for >= 2 series, hover tooltips with hit targets larger than marks, and a table view.
 * Colours come from CSS tokens (validated reference palette, light + dark).
 */
import * as React from "react";

const SLOTS = ["var(--series-1)", "var(--series-2)", "var(--series-3)", "var(--series-4)"];
const OTHER = "var(--series-other)";

/** Measure the container so SVG text renders at its true size (no viewBox scaling). */
function useWidth(): [React.RefObject<HTMLDivElement | null>, number] {
  const ref = React.useRef<HTMLDivElement | null>(null);
  const [width, setWidth] = React.useState(480);
  React.useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(([entry]) => {
      if (entry) setWidth(Math.max(240, Math.round(entry.contentRect.width)));
    });
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, width];
}

function niceMax(v: number): number {
  if (v <= 0) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  return Math.ceil(v / p) * p;
}

function Tooltip({ x, y, lines, width }: { x: number; y: number; lines: string[]; width: number }) {
  const w = Math.max(...lines.map((l) => l.length)) * 6.4 + 16;
  const h = lines.length * 15 + 10;
  const left = Math.min(Math.max(4, x - w / 2), width - w - 4);
  const top = Math.max(2, y - h - 8);
  return (
    <g pointerEvents="none">
      <rect x={left} y={top} width={w} height={h} rx={6} fill="var(--surface)"
            stroke="var(--border)" />
      {lines.map((l, i) => (
        <text key={i} x={left + 8} y={top + 17 + i * 15} fontSize={11}
              fill={i === 0 ? "var(--foreground)" : "var(--muted)"}
              fontWeight={i === 0 ? 600 : 400}>{l}</text>
      ))}
    </g>
  );
}

export type Point = { label: string; value: number };

/** Single-series columns (e.g. DDoS indicators per hour). */
export function ColumnChart({ data, height = 160, unit = "events" }: {
  data: Point[]; height?: number; unit?: string;
}) {
  const [hover, setHover] = React.useState<number | null>(null);
  const [ref, width] = useWidth();
  const pad = { l: 36, r: 8, t: 8, b: 22 };
  const max = niceMax(Math.max(0, ...data.map((d) => d.value)));
  const bw = data.length ? (width - pad.l - pad.r) / data.length : 0;
  const y = (v: number) => pad.t + (height - pad.t - pad.b) * (1 - v / max);
  if (!data.length) return <p className="py-6 text-center text-sm text-subtle">No data in range.</p>;
  return (
    <div ref={ref} className="w-full">
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img"
         aria-label={`Column chart of ${unit}`} onMouseLeave={() => setHover(null)}>
      {[0, 0.5, 1].map((f) => (
        <g key={f}>
          <line x1={pad.l} x2={width - pad.r} y1={y(max * f)} y2={y(max * f)}
                stroke="var(--grid)" strokeWidth={1} />
          <text x={pad.l - 6} y={y(max * f) + 3} fontSize={10} textAnchor="end"
                fill="var(--subtle)" className="tabular">{Math.round(max * f)}</text>
        </g>
      ))}
      {data.map((d, i) => {
        const x = pad.l + i * bw;
        const h = Math.max(0, y(0) - y(d.value));
        const barW = Math.max(2, Math.min(18, bw - 2));
        return (
          <g key={d.label} onMouseEnter={() => setHover(i)}>
            <rect x={x} y={pad.t} width={bw} height={height - pad.t - pad.b} fill="transparent" />
            {h > 0 ? (
              <path d={roundedTop(x + (bw - barW) / 2, y(d.value), barW, h)}
                    fill="var(--series-1)" opacity={hover === null || hover === i ? 1 : 0.55} />
            ) : null}
          </g>
        );
      })}
      <line x1={pad.l} x2={width - pad.r} y1={y(0)} y2={y(0)} stroke="var(--axis)" />
      {data.length > 1 ? (
        <>
          <text x={pad.l} y={height - 6} fontSize={10} fill="var(--subtle)">{data[0]?.label}</text>
          <text x={width - pad.r} y={height - 6} fontSize={10} textAnchor="end"
                fill="var(--subtle)">{data[data.length - 1]?.label}</text>
        </>
      ) : null}
      {hover !== null && data[hover] ? (
        <Tooltip x={pad.l + hover * bw + bw / 2} y={y(data[hover].value)} width={width}
                 lines={[data[hover].label, `${data[hover].value} ${unit}`]} />
      ) : null}
    </svg>
    </div>
  );
}

function roundedTop(x: number, y: number, w: number, h: number): string {
  const r = Math.min(4, w / 2, h);
  return `M${x},${y + h} L${x},${y + r} Q${x},${y} ${x + r},${y} L${x + w - r},${y} ` +
    `Q${x + w},${y} ${x + w},${y + r} L${x + w},${y + h} Z`;
}

export type StackRow = { label: string; values: Record<string, number> };

/** Stacked columns over time. Series beyond the first four fold into "Other". */
export function StackedColumns({ rows, series, height = 200 }: {
  rows: StackRow[]; series: string[]; height?: number;
}) {
  const [hover, setHover] = React.useState<number | null>(null);
  const [table, setTable] = React.useState(false);
  const shown = series.slice(0, 4);
  const folded = series.length > 4;
  const keys = folded ? [...shown, "Other"] : shown;
  const colored = (k: string, i: number) => (k === "Other" ? OTHER : SLOTS[i] ?? OTHER);
  const data = rows.map((r) => {
    const v: Record<string, number> = {};
    shown.forEach((s) => (v[s] = r.values[s] ?? 0));
    if (folded) {
      v.Other = Object.entries(r.values).filter(([k]) => !shown.includes(k))
        .reduce((a, [, n]) => a + n, 0);
    }
    return { label: r.label, v, total: keys.reduce((a, k) => a + (v[k] ?? 0), 0) };
  });
  const [ref, width] = useWidth();
  const pad = { l: 36, r: 8, t: 8, b: 22 };
  const max = niceMax(Math.max(0, ...data.map((d) => d.total)));
  const bw = data.length ? (width - pad.l - pad.r) / data.length : 0;
  const scale = (v: number) => (height - pad.t - pad.b) * (v / max);
  const base = height - pad.b;
  if (!rows.length) return <p className="py-6 text-center text-sm text-subtle">No data in range.</p>;
  return (
    <div ref={ref}>
      <div className="mb-2 flex flex-wrap items-center gap-3 text-xs text-muted">
        {keys.map((k, i) => (
          <span key={k} className="inline-flex items-center gap-1">
            <svg width="10" height="10" aria-hidden><rect width="10" height="10" rx="2"
                                                          fill={colored(k, i)} /></svg>
            {k.replaceAll("_", " ")}
          </span>
        ))}
        <button className="ml-auto underline" onClick={() => setTable(!table)}>
          {table ? "Show chart" : "Show table"}
        </button>
      </div>
      {table ? (
        <table className="w-full text-xs tabular">
          <thead><tr className="text-left text-muted"><th>Time</th>{keys.map((k) => <th key={k}>{k}</th>)}</tr></thead>
          <tbody>{data.map((d) => (
            <tr key={d.label}><td>{d.label}</td>{keys.map((k) => <td key={k}>{d.v[k] ?? 0}</td>)}</tr>
          ))}</tbody>
        </table>
      ) : (
        <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img"
             aria-label="Stacked column chart of security events by category"
             onMouseLeave={() => setHover(null)}>
          {[0, 0.5, 1].map((f) => (
            <g key={f}>
              <line x1={pad.l} x2={width - pad.r} y1={base - scale(max * f)}
                    y2={base - scale(max * f)} stroke="var(--grid)" />
              <text x={pad.l - 6} y={base - scale(max * f) + 3} fontSize={10} textAnchor="end"
                    fill="var(--subtle)" className="tabular">{Math.round(max * f)}</text>
            </g>
          ))}
          {data.map((d, i) => {
            const barW = Math.max(3, Math.min(18, bw - 2));
            const x = pad.l + i * bw + (bw - barW) / 2;
            let cursor = base;
            const segs = keys.map((k, ki) => {
              const h = scale(d.v[k] ?? 0);
              if (h <= 0) return null;
              const top = cursor - h;
              const seg = { k, ki, y: top + 2, h: Math.max(0, h - 2) }; // 2px surface gap
              cursor = top;
              return seg;
            }).filter(Boolean) as { k: string; ki: number; y: number; h: number }[];
            return (
              <g key={d.label} onMouseEnter={() => setHover(i)}>
                <rect x={pad.l + i * bw} y={pad.t} width={bw} height={height - pad.t - pad.b}
                      fill="transparent" />
                {segs.map((s, si) => si === segs.length - 1 ? (
                  <path key={s.k} d={roundedTop(x, s.y, barW, s.h)} fill={colored(s.k, s.ki)} />
                ) : (
                  <rect key={s.k} x={x} y={s.y} width={barW} height={s.h} fill={colored(s.k, s.ki)} />
                ))}
              </g>
            );
          })}
          <line x1={pad.l} x2={width - pad.r} y1={base} y2={base} stroke="var(--axis)" />
          {data.length > 1 ? (
            <>
              <text x={pad.l} y={height - 6} fontSize={10} fill="var(--subtle)">{data[0]?.label}</text>
              <text x={width - pad.r} y={height - 6} fontSize={10} textAnchor="end"
                    fill="var(--subtle)">{data[data.length - 1]?.label}</text>
            </>
          ) : null}
          {hover !== null && data[hover] ? (
            <Tooltip x={pad.l + hover * bw + bw / 2} y={base - scale(data[hover].total)}
                     width={width} lines={[data[hover].label, ...keys.filter((k) =>
                       (data[hover]?.v[k] ?? 0) > 0).map((k) => `${k.replaceAll("_", " ")}: ${data[hover]?.v[k]}`)]} />
          ) : null}
        </svg>
      )}
    </div>
  );
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_COLOR: Record<string, string> = {
  critical: "var(--status-critical)", high: "var(--status-serious)",
  medium: "var(--status-warning)", low: "var(--subtle)", info: "var(--axis)",
};

/** Severity distribution: horizontal bars, each labelled with name and count (status colour
 * never carries meaning alone). */
export function SeverityBars({ counts }: { counts: Record<string, number> }) {
  const max = Math.max(1, ...Object.values(counts));
  return (
    <div className="space-y-2" role="list" aria-label="Findings by severity">
      {SEVERITY_ORDER.map((sev) => {
        const n = counts[sev] ?? 0;
        return (
          <div key={sev} role="listitem" className="grid grid-cols-[72px_1fr_40px] items-center gap-2 text-xs">
            <span className="capitalize text-muted">{sev}</span>
            <svg viewBox="0 0 100 8" preserveAspectRatio="none" className="h-2 w-full" aria-hidden>
              <rect width="100" height="8" rx="4" fill="var(--grid)" />
              {n > 0 ? <rect width={Math.max(2, (n / max) * 100)} height="8" rx="4"
                             fill={SEVERITY_COLOR[sev]} /> : null}
            </svg>
            <span className="text-right tabular">{n}</span>
          </div>
        );
      })}
    </div>
  );
}
