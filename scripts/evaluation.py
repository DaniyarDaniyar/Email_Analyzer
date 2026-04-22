"""
Evaluation & Reporting Script for Email Analyzer
=================================================
Reads ``results.json`` produced by ``evaluate_api.py``, computes descriptive
statistics on the collected ``final_score`` values, generates textual reports,
and optionally produces score-distribution charts.

Charts require *matplotlib* (``pip install matplotlib``).  All other
functionality works without any third-party packages.

Usage examples
--------------
# Basic report printed to stdout:
    python scripts/evaluation.py --results ./results.json

# Save a text report and a histogram PNG:
    python scripts/evaluation.py \\
        --results ./results.json \\
        --report-out ./report.txt \\
        --chart-out  ./distribution.png

# Compare two result files side-by-side:
    python scripts/evaluation.py \\
        --results ./results_v1.json ./results_v2.json \\
        --labels  run_v1 run_v2 \\
        --report-out ./comparison.txt \\
        --chart-out  ./comparison.png
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("evaluation")


# ---------------------------------------------------------------------------
# Statistics helpers (pure stdlib)
# ---------------------------------------------------------------------------

def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _variance(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    return sum((v - m) ** 2 for v in values) / (len(values) - 1)


def _std(values: list[float]) -> float:
    return math.sqrt(_variance(values))


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def _percentile(values: list[float], p: float) -> float:
    """Return the *p*-th percentile (0-100) of *values* using linear interpolation."""
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    rank = (p / 100.0) * (n - 1)
    lower = int(rank)
    upper = min(lower + 1, n - 1)
    fraction = rank - lower
    return s[lower] + fraction * (s[upper] - s[lower])


def _distribution(values: list[float], bins: int = 10) -> list[dict[str, Any]]:
    """Return a histogram as a list of bucket dicts."""
    if not values:
        return []
    lo = min(values)
    hi = max(values)
    if lo == hi:
        return [{"range": f"[{lo:.2f}, {hi:.2f}]", "count": len(values), "pct": 100.0}]

    step = (hi - lo) / bins
    buckets: list[dict[str, Any]] = []
    for i in range(bins):
        b_lo = lo + i * step
        b_hi = lo + (i + 1) * step
        count = sum(1 for v in values if b_lo <= v < b_hi or (i == bins - 1 and v == b_hi))
        buckets.append({
            "range": f"[{b_lo:.2f}, {b_hi:.2f})",
            "lo": b_lo,
            "hi": b_hi,
            "count": count,
            "pct": 100.0 * count / len(values),
        })
    return buckets


def compute_stats(scores: list[float]) -> dict[str, Any]:
    """Return a dict of descriptive statistics for *scores*.

    Example
    -------
    >>> stats = compute_stats([0.1, 0.5, 0.9, 0.7, 0.3])
    >>> print(f"mean={stats['mean']:.3f}  std={stats['std']:.3f}")
    """
    if not scores:
        return {
            "count": 0,
            "mean": None,
            "std": None,
            "min": None,
            "max": None,
            "median": None,
            "p25": None,
            "p75": None,
            "p90": None,
            "p95": None,
        }
    return {
        "count": len(scores),
        "mean": _mean(scores),
        "std": _std(scores),
        "min": min(scores),
        "max": max(scores),
        "median": _median(scores),
        "p25": _percentile(scores, 25),
        "p75": _percentile(scores, 75),
        "p90": _percentile(scores, 90),
        "p95": _percentile(scores, 95),
    }


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def _classification_breakdown(results: list[dict[str, Any]]) -> dict[str, int]:
    breakdown: dict[str, int] = {}
    for r in results:
        cls = str(r.get("classification") or "unknown").lower()
        breakdown[cls] = breakdown.get(cls, 0) + 1
    return breakdown


def _status_breakdown(results: list[dict[str, Any]]) -> dict[str, int]:
    breakdown: dict[str, int] = {}
    for r in results:
        st = str(r.get("status") or "unknown").lower()
        breakdown[st] = breakdown.get(st, 0) + 1
    return breakdown


def _scores_from_results(results: list[dict[str, Any]]) -> list[float]:
    scores: list[float] = []
    for r in results:
        try:
            v = r.get("final_score")
            if v is not None:
                scores.append(float(v))
        except (TypeError, ValueError):
            pass
    return scores


def _format_stats_block(stats: dict[str, Any], indent: str = "  ") -> str:
    lines: list[str] = []
    if stats.get("count", 0) == 0:
        return indent + "(no valid scores)"
    for key in ("count", "mean", "std", "min", "median", "max", "p25", "p75", "p90", "p95"):
        val = stats.get(key)
        fmt = f"{val:.4f}" if isinstance(val, float) else str(val)
        lines.append(f"{indent}{key:<12}: {fmt}")
    return "\n".join(lines)


def _ascii_histogram(buckets: list[dict[str, Any]], width: int = 40) -> str:
    if not buckets:
        return "  (no data)"
    max_count = max(b["count"] for b in buckets) or 1
    lines: list[str] = []
    for b in buckets:
        bar_len = int(width * b["count"] / max_count)
        bar = "█" * bar_len
        lines.append(f"  {b['range']:20s} | {bar:<{width}} {b['count']:5d} ({b['pct']:5.1f}%)")
    return "\n".join(lines)


def build_report(
    run_data: list[tuple[str, list[dict[str, Any]]]],
    bins: int = 10,
) -> str:
    """Build a text report from one or more labelled result sets.

    Parameters
    ----------
    run_data:
        List of ``(label, results)`` tuples.
    bins:
        Number of histogram buckets.

    Returns
    -------
    str
        Multi-line report text.

    Example
    -------
    >>> report_text = build_report([("run_1", results_list)])
    >>> print(report_text)
    """
    lines: list[str] = []
    sep = "=" * 72
    thin_sep = "-" * 72

    lines.append(sep)
    lines.append("  EMAIL ANALYZER — EVALUATION REPORT")
    lines.append(f"  Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(sep)
    lines.append("")

    for label, results in run_data:
        scores = _scores_from_results(results)
        stats = compute_stats(scores)
        cls_break = _classification_breakdown(results)
        status_break = _status_breakdown(results)
        buckets = _distribution(scores, bins=bins)

        lines.append(f"RUN: {label}")
        lines.append(thin_sep)

        lines.append(f"  Total entries   : {len(results)}")
        lines.append(f"  Scored entries  : {stats.get('count', 0)}")
        lines.append("")

        lines.append("  Status breakdown:")
        for st, cnt in sorted(status_break.items()):
            lines.append(f"    {st:<20}: {cnt}")
        lines.append("")

        lines.append("  Classification breakdown:")
        for cls, cnt in sorted(cls_break.items()):
            lines.append(f"    {cls:<20}: {cnt}")
        lines.append("")

        lines.append("  Score statistics:")
        lines.append(_format_stats_block(stats))
        lines.append("")

        if buckets:
            lines.append("  Score distribution:")
            lines.append(_ascii_histogram(buckets))
            lines.append("")

        lines.append("")

    # Comparison section (only when there are multiple runs)
    if len(run_data) > 1:
        lines.append("COMPARISON")
        lines.append(thin_sep)
        def _trim(lbl: str, width: int = 14) -> str:
            return lbl if len(lbl) <= width else lbl[: width - 3] + "..."

        header = f"  {'Metric':<14}" + "".join(f"  {_trim(label):<14}" for label, _ in run_data)
        lines.append(header)
        for metric in ("count", "mean", "std", "min", "median", "max"):
            row = f"  {metric:<14}"
            for label, results in run_data:
                v = compute_stats(_scores_from_results(results)).get(metric)
                cell = f"{v:.4f}" if isinstance(v, float) else str(v)
                row += f"  {cell:<14}"
            lines.append(row)
        lines.append("")

    lines.append(sep)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Chart generation (optional – requires matplotlib)
# ---------------------------------------------------------------------------

def save_chart(
    run_data: list[tuple[str, list[dict[str, Any]]]],
    chart_path: str | Path,
    bins: int = 20,
) -> None:
    """Save a histogram (or overlapping histograms) to *chart_path*.

    Requires *matplotlib*.  Silently logs a warning if it is not installed.

    Example
    -------
    >>> save_chart([("run_1", results)], "./distribution.png")
    """
    try:
        import matplotlib  # type: ignore
        matplotlib.use("Agg")  # non-interactive backend
        import matplotlib.pyplot as plt  # type: ignore
    except ImportError:
        logger.warning(
            "matplotlib is not installed; skipping chart generation. "
            "Install with: pip install matplotlib"
        )
        return

    fig, ax = plt.subplots(figsize=(10, 5))

    colors = ["steelblue", "tomato", "seagreen", "darkorange", "purple"]
    for i, (label, results) in enumerate(run_data):
        scores = _scores_from_results(results)
        if scores:
            color = colors[i % len(colors)]
            ax.hist(
                scores,
                bins=bins,
                alpha=0.6,
                label=f"{label} (n={len(scores)})",
                color=color,
                edgecolor="white",
            )

    ax.set_xlabel("Final Score", fontsize=13)
    ax.set_ylabel("Count", fontsize=13)
    ax.set_title("Email Threat Score Distribution", fontsize=15)
    ax.legend()
    # Set x-axis range dynamically based on actual data, with a small margin
    all_scores: list[float] = []
    for _, results in run_data:
        all_scores.extend(_scores_from_results(results))
    if all_scores:
        margin = (max(all_scores) - min(all_scores)) * 0.05 or 0.05
        ax.set_xlim(max(0.0, min(all_scores) - margin), min(1.0, max(all_scores) + margin)
                    if max(all_scores) <= 1.0 else max(all_scores) + margin)
    plt.tight_layout()

    out = Path(chart_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(str(out), dpi=150)
    plt.close(fig)
    logger.info("Chart saved to %s", out)


# ---------------------------------------------------------------------------
# Loading helpers
# ---------------------------------------------------------------------------

def load_results(results_path: str | Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load a results JSON file and return ``(results_list, meta_dict)``.

    Example
    -------
    >>> results, meta = load_results("./results.json")
    >>> print(meta["api_url"])
    """
    p = Path(results_path)
    if not p.exists():
        raise FileNotFoundError(f"Results file not found: {p}")
    with p.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    # Accept both plain list and {meta, results} formats
    if isinstance(data, list):
        return data, {}
    results = data.get("results", [])
    meta = data.get("meta", {})
    return results, meta


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Analyze evaluation results and generate reports/charts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--results",
        nargs="+",
        required=True,
        metavar="FILE",
        help="One or more results JSON files (produced by evaluate_api.py).",
    )
    p.add_argument(
        "--labels",
        nargs="*",
        default=None,
        metavar="LABEL",
        help="Labels for each results file (defaults to filename stems).",
    )
    p.add_argument(
        "--report-out",
        default=None,
        metavar="FILE",
        help="Save text report to this file (prints to stdout if omitted).",
    )
    p.add_argument(
        "--chart-out",
        default=None,
        metavar="FILE",
        help="Save distribution chart to this file (requires matplotlib).",
    )
    p.add_argument(
        "--bins",
        type=int,
        default=10,
        metavar="N",
        help="Number of histogram bins (default: 10).",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG logging.",
    )
    return p


def main(argv: list[str] | None = None) -> None:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Build (label, results) pairs
    labels = args.labels or []
    run_data: list[tuple[str, list[dict[str, Any]]]] = []
    for i, results_file in enumerate(args.results):
        label = labels[i] if i < len(labels) else Path(results_file).stem
        try:
            results, meta = load_results(results_file)
            run_data.append((label, results))
            logger.info("Loaded %d results from %s.", len(results), results_file)
        except FileNotFoundError as exc:
            logger.error("%s", exc)
            sys.exit(1)

    report_text = build_report(run_data, bins=args.bins)

    if args.report_out:
        out = Path(args.report_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report_text, encoding="utf-8")
        logger.info("Report saved to %s", out)
    else:
        print(report_text)

    if args.chart_out:
        save_chart(run_data, args.chart_out, bins=args.bins * 2)


if __name__ == "__main__":
    main()
