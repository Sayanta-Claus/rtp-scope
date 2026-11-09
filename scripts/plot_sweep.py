#!/usr/bin/env python3
"""plot_sweep.py -- chart the `rtp_scope --sweep` CSV: latency vs late-or-lost %.

Input  : CSV with header  strategy,avg_latency_ms,late_or_lost_pct
         rows named fixed-<N>ms and adaptive-k<K>.
Output : a PNG (matplotlib) or, if matplotlib is not installed, a
         self-contained SVG written with plain Python.

Reading the chart: every point is one buffer setting. Down is better (fewer
packets late or lost), left is better (less added latency). The fixed-delay
curve shows the trade-off; the adaptive points show where the adaptive buffer
lands for several safety factors k.

Usage: scripts/plot_sweep.py sweep.csv out.png
"""
import csv
import re
import sys

BLUE = "#2f6fb0"    # fixed delay
ORANGE = "#d9701c"  # adaptive
INK = "#222222"
MUTED = "#666666"
GRID = "#dddddd"


def load(path):
    fixed, adaptive = [], []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            x, y = float(row["avg_latency_ms"]), float(row["late_or_lost_pct"])
            name = row["strategy"]
            m = re.fullmatch(r"fixed-([\d.]+)ms", name)
            if m:
                fixed.append((x, y, m.group(1) + " ms"))
                continue
            m = re.fullmatch(r"adaptive-k([\d.]+)", name)
            if m:
                adaptive.append((x, y, "k=" + m.group(1)))
    if not fixed and not adaptive:
        sys.exit("plot_sweep.py: no recognisable rows in " + path)
    return sorted(fixed), sorted(adaptive)


def plot_matplotlib(fixed, adaptive, out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(8, 4.8), dpi=150)
    for pts, color, marker, label in ((fixed, BLUE, "o", "Fixed delay (label = delay)"),
                                      (adaptive, ORANGE, "s", "Adaptive (label = k)")):
        if not pts:
            continue
        ax.plot([p[0] for p in pts], [p[1] for p in pts], color=color, marker=marker,
                markersize=6, linewidth=1.75, markeredgecolor="white", markeredgewidth=1.0, label=label)
        # fixed labels sit up-and-right of their points, adaptive ones up-and-left
        # (right-aligned), so the two series do not print over each other
        offset, align = ((6, 6), "left") if pts is fixed else ((-6, 8), "right")
        for x, y, text in pts:
            ax.annotate(text, (x, y), textcoords="offset points", xytext=offset, ha=align,
                        fontsize=7.5, color=MUTED)
    ax.set_xlabel("Average added latency (ms)", color=INK)
    ax.set_ylabel("Late or lost packets (%)", color=INK)
    ax.set_title("Jitter buffer: latency vs. late-or-lost packets", loc="left", color=INK, fontsize=12)
    ax.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(MUTED)
    ax.tick_params(colors=MUTED)
    ax.set_xlim(left=0)
    ax.set_ylim(bottom=0)
    ax.legend(frameon=False, loc="upper right")
    fig.tight_layout()
    fig.savefig(out, facecolor="white")


def plot_svg(fixed, adaptive, out):
    W, H, L, R, T, B = 800, 480, 70, 30, 50, 60
    xs = [p[0] for p in fixed + adaptive]
    ys = [p[1] for p in fixed + adaptive]
    xmax, ymax = max(xs) * 1.08 or 1, max(ys) * 1.08 or 1

    def px(x): return L + (W - L - R) * x / xmax
    def py(y): return H - B - (H - T - B) * y / ymax

    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
         f'font-family="sans-serif" font-size="12"><rect width="{W}" height="{H}" fill="white"/>',
         f'<text x="{L}" y="28" font-size="16" fill="{INK}">Jitter buffer: latency vs. late-or-lost packets</text>']
    for i in range(6):
        gx, gy = xmax * i / 5, ymax * i / 5
        o.append(f'<line x1="{px(gx):.1f}" y1="{T}" x2="{px(gx):.1f}" y2="{H - B}" stroke="{GRID}"/>')
        o.append(f'<line x1="{L}" y1="{py(gy):.1f}" x2="{W - R}" y2="{py(gy):.1f}" stroke="{GRID}"/>')
        o.append(f'<text x="{px(gx):.1f}" y="{H - B + 18}" text-anchor="middle" fill="{MUTED}">{gx:.0f}</text>')
        o.append(f'<text x="{L - 8}" y="{py(gy) + 4:.1f}" text-anchor="end" fill="{MUTED}">{gy:.0f}</text>')
    o.append(f'<text x="{(L + W - R) / 2}" y="{H - 14}" text-anchor="middle" fill="{INK}">Average added latency (ms)</text>')
    o.append(f'<text transform="translate(18 {(T + H - B) / 2}) rotate(-90)" text-anchor="middle" fill="{INK}">Late or lost packets (%)</text>')
    for pts, color, name in ((fixed, BLUE, "Fixed delay"), (adaptive, ORANGE, "Adaptive (k)")):
        if not pts:
            continue
        path = " ".join(f"{px(x):.1f},{py(y):.1f}" for x, y, _ in pts)
        o.append(f'<polyline points="{path}" fill="none" stroke="{color}" stroke-width="1.75"/>')
        for x, y, text in pts:
            o.append(f'<circle cx="{px(x):.1f}" cy="{py(y):.1f}" r="4" fill="{color}" stroke="white" stroke-width="1"/>')
            o.append(f'<text x="{px(x) + 6:.1f}" y="{py(y) - 6:.1f}" font-size="10" fill="{MUTED}">{text}</text>')
    lx = W - R - 160
    for i, (color, name) in enumerate(((BLUE, "Fixed delay"), (ORANGE, "Adaptive (k)"))):
        o.append(f'<circle cx="{lx}" cy="{T + 8 + 18 * i}" r="4" fill="{color}"/>'
                 f'<text x="{lx + 10}" y="{T + 12 + 18 * i}" fill="{INK}">{name}</text>')
    o.append("</svg>")
    with open(out, "w") as f:
        f.write("\n".join(o))


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    fixed, adaptive = load(sys.argv[1])
    out = sys.argv[2]
    try:
        import matplotlib  # noqa: F401
    except ImportError:
        if out.endswith(".png"):
            out = out[:-4] + ".svg"
        plot_svg(fixed, adaptive, out)
        print("matplotlib not available; wrote SVG:", out)
        return
    plot_matplotlib(fixed, adaptive, out)
    print("wrote", out)


if __name__ == "__main__":
    main()
