# -*- coding: utf-8 -*-
"""
Plot six experimental metrics from multiple six_plot_data_clean CSV/XLSX files.

Expected input columns:
  scheme,N,B,metric,plot_value,plot_unit,n,m,r,t,q_bits,d,sigma_inf,short_range,message_bits

Outputs:
  computation-setup.pdf
  computation-keygen.pdf
  computation-register.pdf
  computation-encrypt-64bit.pdf
  computation-decrypt-64bit.pdf
  computation-ciphertext-size-64bit.pdf
  computation-six-panel.pdf

Notes:
  - x-axis uses N = 10^3, 10^4, 10^5, 10^6 only.
  - CiphertextSizes are converted to KB for plotting.
  combined_six_plot_data.csv

This version reads .csv and simple .xlsx files without requiring openpyxl and enforces six schemes:
  DöttlingRBE, KlooßRBE, ZhangRBE-I, ZhangRBE-II, PostRBE, PostRBE*
"""

from __future__ import annotations

import argparse
import math
import re
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Iterable, List

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.pylab as pylab
from matplotlib.ticker import LogLocator, NullFormatter

# ========= Style =========
params = {
    "axes.labelsize": 12,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 6.5,
    "figure.figsize": (4.1, 2.7),
    "figure.dpi": 300,
    "figure.subplot.left": 0.18,
    "figure.subplot.right": 0.98,
    "figure.subplot.bottom": 0.22,
    "figure.subplot.top": 0.92,
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
}
pylab.rcParams.update(params)

# ========= Scheme names =========
# Internal canonical order follows the names requested by senior student.
SCHEME_ORDER = [
    "DöttlingRBE",
    "KlooßRBE",
    "ZhangRBE-I",
    "ZhangRBE-II",
    "PostRBE",
    "PostRBE*",
]

SCHEME_LABEL = {
    "DöttlingRBE": "DöttlingRBE",
    "KlooßRBE": "KlooßRBE",
    "ZhangRBE-I": "ZhangRBE-I",
    "ZhangRBE-II": "ZhangRBE-II",
    "PostRBE": r"$\mathsf{PostRBE}$",
    "PostRBE*": r"$\mathsf{PostRBE}^{*}$",
}

# Color palette extended from the previous template.
SCHEME_COLOR = {
    "DöttlingRBE": "#05B9E2",
    "KlooßRBE": "#32B897",
    "ZhangRBE-I": "#54B345",
    "ZhangRBE-II": "#BB9727",
    "PostRBE": "#F27970",
    "PostRBE*": "#8C6BB1",
}

SCHEME_HATCH = {
    "DöttlingRBE": "////",
    "KlooßRBE": "\\\\\\\\",
    "ZhangRBE-I": "----",
    "ZhangRBE-II": "....",
    "PostRBE": "xxxx",
    "PostRBE*": "++++",
}

NAME_ALIASES: Dict[str, str] = {
    # Our schemes
    "PostRBE": "PostRBE",
    "$\\mathsf{PostRBE}$": "PostRBE",
    "\\mathsf{PostRBE}": "PostRBE",
    "PostRBE*": "PostRBE*",
    "PostRBE^*": "PostRBE*",
    "PostRBE^{*}": "PostRBE*",
    "$\\mathsf{PostRBE}^{*}$": "PostRBE*",
    "postrbe": "PostRBE",
    "postrbe*": "PostRBE*",

    # DKLLMR / Doettling
    "DKLLMR23RBE": "DöttlingRBE",
    "DKLLMRRBE": "DöttlingRBE",
    "DottlingRBE": "DöttlingRBE",
    "DoettlingRBE": "DöttlingRBE",
    "DöttlingRBE": "DöttlingRBE",
    'Do\\"ttlingRBE': "DöttlingRBE",

    # SP26 / Klooss
    "SP26BLE-RBE": "KlooßRBE",
    "SP26BLE_RBE": "KlooßRBE",
    "SP26-RBE": "KlooßRBE",
    "KloossRBE": "KlooßRBE",
    "KlooßRBE": "KlooßRBE",
    "Kloo{\\ss}RBE": "KlooßRBE",
    "Kloo\\ssRBE": "KlooßRBE",

    # FC26 / Zhang
    "FC26-BaseRBE": "ZhangRBE-I",
    "FC26_BaseRBE": "ZhangRBE-I",
    "BaseRBE": "ZhangRBE-I",
    "ZhangRBE-I": "ZhangRBE-I",
    "ZhanGRBE-I": "ZhangRBE-I",
    "FC26-MoreEfficientRBE": "ZhangRBE-II",
    "FC26_MoreEfficientRBE": "ZhangRBE-II",
    "MoreEfficientRBE": "ZhangRBE-II",
    "ZhangRBE-II": "ZhangRBE-II",
    "ZhanGRBE-II": "ZhangRBE-II",
}

METRIC_INFO = {
    "Setup": ("Setup", "computation-setup.pdf", "Time (ms)"),
    "KeyGen": ("KeyGen", "computation-keygen.pdf", "Time (ms)"),
    "Register": ("Register", "computation-register.pdf", "Time (ms)"),
    "Encrypt": ("", "computation-encrypt-64.pdf", "Time (ms)"),
    "DecryptUpdate": ("", "computation-decrypt-64.pdf", "Time (ms)"),
    "CiphertextSizes": ("", "ciphertext-64.pdf", "Size (KB)"),
}

USERS = [10**3, 10**4, 10**5, 10**6]
USER_LABELS = [r"$10^{3}$", r"$10^{4}$", r"$10^{5}$", r"$10^{6}$"]

# Keep the original bar colors/hatches. Only change legend layout and log-y headroom.
LEGEND_NCOL = 3          # 6 schemes -> 2 rows x 3 columns
LOG_Y_HEADROOM = 50.0    # raise y-axis top so the in-plot legend does not cover bars


def canonical_scheme(name: object) -> str:
    s = str(name).strip()
    return NAME_ALIASES.get(s, s)


def _excel_col_to_index(cell_ref: str) -> int:
    letters = re.sub(r"[^A-Z]", "", cell_ref.upper())
    idx = 0
    for ch in letters:
        idx = idx * 26 + (ord(ch) - ord("A") + 1)
    return idx - 1


def _xlsx_fallback_to_dataframe(path: Path) -> pd.DataFrame:
    ns = {"main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    with zipfile.ZipFile(path, "r") as z:
        shared_strings: List[str] = []
        if "xl/sharedStrings.xml" in z.namelist():
            root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            for si in root.findall("main:si", ns):
                shared_strings.append("".join((t.text or "") for t in si.findall(".//main:t", ns)))
        sheet_name = "xl/worksheets/sheet1.xml"
        if sheet_name not in z.namelist():
            candidates = [n for n in z.namelist() if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")]
            if not candidates:
                raise ValueError("No worksheet XML found in xlsx file.")
            sheet_name = sorted(candidates)[0]
        root = ET.fromstring(z.read(sheet_name))
        rows = []
        max_col = 0
        for row in root.findall(".//main:sheetData/main:row", ns):
            row_values: Dict[int, object] = {}
            for c in row.findall("main:c", ns):
                col_idx = _excel_col_to_index(c.attrib.get("r", "A1"))
                max_col = max(max_col, col_idx + 1)
                cell_type = c.attrib.get("t")
                value = ""
                if cell_type == "inlineStr":
                    value = "".join((t.text or "") for t in c.findall(".//main:t", ns))
                else:
                    v = c.find("main:v", ns)
                    if v is not None and v.text is not None:
                        raw = v.text
                        if cell_type == "s":
                            try:
                                value = shared_strings[int(raw)]
                            except Exception:
                                value = raw
                        else:
                            value = raw
                row_values[col_idx] = value
            if row_values:
                rows.append(row_values)
    if not rows:
        return pd.DataFrame()
    matrix = [[rv.get(i, "") for i in range(max_col)] for rv in rows]
    header_index = 0
    for i, row in enumerate(matrix):
        if any(str(x).strip() for x in row):
            header_index = i
            break
    header = [str(x).strip().lstrip("\ufeff") for x in matrix[header_index]]
    while header and header[-1] == "":
        header.pop()
    data = [r[:len(header)] for r in matrix[header_index + 1:] if any(str(x).strip() for x in r[:len(header)])]
    return pd.DataFrame(data, columns=header)


def _read_excel_robust(path: Path) -> pd.DataFrame:
    try:
        df = pd.read_excel(path)
    except Exception as exc:
        msg = str(exc)
        if "openpyxl" in msg or "Missing optional dependency" in msg:
            df = _xlsx_fallback_to_dataframe(path)
        else:
            raise
    df.columns = [str(c).strip().lstrip("\ufeff") for c in df.columns]
    return df


def read_one(path: Path) -> pd.DataFrame:
    suffix = path.suffix.lower()
    if suffix in {".xlsx", ".xls"}:
        return _read_excel_robust(path)
    if suffix == ".csv":
        with open(path, "rb") as f:
            header = f.read(4)
        if header.startswith(b"PK\x03\x04"):
            return _read_excel_robust(path)
        encodings = ["utf-8", "utf-8-sig", "gb18030", "gbk", "cp936", "utf-16", "utf-16-le", "utf-16-be", "cp1252", "latin1"]
        last_error = None
        for enc in encodings:
            try:
                df = pd.read_csv(path, encoding=enc)
                if len(df.columns) == 1:
                    df = pd.read_csv(path, encoding=enc, sep=None, engine="python")
                df.columns = [str(c).strip().lstrip("\ufeff") for c in df.columns]
                return df
            except Exception as exc:
                last_error = exc
        raise ValueError(f"Could not read CSV with common encodings. Last error: {last_error}")
    raise ValueError(f"Unsupported file type: {path}")

def collect_files(data_dir: Path, explicit_csvs: Iterable[str] | None = None) -> List[Path]:
    if explicit_csvs:
        return [Path(p) for p in explicit_csvs]
    files: List[Path] = []
    for ext in ("*.csv", "*.xlsx", "*.xls"):
        files.extend(data_dir.glob(ext))
    # avoid reading our own combined output if the script is re-run
    files = [p for p in files if not p.name.startswith("combined_six_plot_data")]
    return sorted(files)


def load_data(paths: List[Path]) -> pd.DataFrame:
    frames = []
    required = {"scheme", "N", "metric", "plot_value", "plot_unit"}
    for p in paths:
        try:
            d = read_one(p)
        except Exception as exc:
            print(f"[WARN] failed to read {p}: {exc}")
            continue
        missing = required - set(d.columns)
        if missing:
            print(f"[WARN] skipped {p.name}; missing columns: {sorted(missing)}")
            continue
        d = d.copy()
        d["source_file"] = p.name
        frames.append(d)
        print(f"[INFO] loaded {p.name}: {len(d)} rows")
    if not frames:
        raise SystemExit("No valid clean data files loaded.")
    df = pd.concat(frames, ignore_index=True)
    df["scheme"] = df["scheme"].map(canonical_scheme)
    df["N"] = pd.to_numeric(df["N"], errors="coerce").astype("Int64")
    df["plot_value"] = pd.to_numeric(df["plot_value"], errors="coerce")
    return df


def aggregate_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    """If the same scheme/N/metric appears twice, keep the first non-null value."""
    param_cols = [c for c in ["B", "n", "m", "r", "t", "q_bits", "d", "sigma_inf", "short_range", "message_bits"] if c in df.columns]
    group_cols = ["scheme", "N", "metric"]
    agg = {"plot_value": "first", "plot_unit": "first", "source_file": lambda x: ";".join(sorted(set(map(str, x))))}
    for c in param_cols:
        agg[c] = "first"
    return df.sort_values(group_cols).groupby(group_cols, as_index=False).agg(agg)


def convert_ciphertext_sizes_to_kb(df: pd.DataFrame) -> pd.DataFrame:
    """Convert CiphertextSizes plot_value to KB for plotting.

    Existing clean CSVs usually store CiphertextSizes in MiB. This function keeps
    values already in KB/KiB unchanged, converts MiB/MB to KB by multiplying by
    1024, and converts bytes to KB by dividing by 1024.
    """
    df = df.copy()
    if "plot_unit" not in df.columns:
        return df
    mask = df["metric"].astype(str).eq("CiphertextSizes")
    for idx in df.index[mask]:
        unit = str(df.at[idx, "plot_unit"]).strip().lower()
        val = df.at[idx, "plot_value"]
        if pd.isna(val):
            continue
        if unit in {"mib", "mb"}:
            df.at[idx, "plot_value"] = float(val) * 1024.0
        elif unit in {"bytes", "byte", "b"}:
            df.at[idx, "plot_value"] = float(val) / 1024.0
        elif unit in {"kib", "kb"}:
            df.at[idx, "plot_value"] = float(val)
        else:
            # Be conservative: our previous clean files used MiB for ciphertext sizes.
            df.at[idx, "plot_value"] = float(val) * 1024.0
    df.loc[mask, "plot_unit"] = "KB"
    return df


def setup_grid(ax):
    ax.grid(axis="y", linestyle="--", linewidth=0.5, color="black", alpha=0.35)


def adjust_log_ylim(ax, values: List[float]):
    pos = [v for v in values if pd.notna(v) and v > 0]
    if not pos:
        return
    ymin = min(pos) / 1.8
    ymax = max(pos) * 100
    if ymin <= 0:
        ymin = min(pos) * 0.5
    ax.set_ylim(ymin, ymax)


def plot_metric(df: pd.DataFrame, metric: str, out_dir: Path):
    title, filename, ylabel = METRIC_INFO[metric]
    sub = df[df["metric"] == metric].copy()

    schemes_present = [s for s in SCHEME_ORDER if s in set(sub["scheme"])]
    missing = [s for s in SCHEME_ORDER if s not in schemes_present]
    if missing:
        print(f"[WARN] {metric}: missing schemes: {missing}")

    x = np.arange(len(USERS))
    n_models = max(len(schemes_present), 1)
    width = min(0.12, 0.78 / n_models)

    fig, ax = plt.subplots()
    all_y: List[float] = []
    for i, scheme in enumerate(schemes_present):
        y = []
        for N in USERS:
            vals = sub[(sub["scheme"] == scheme) & (sub["N"] == N)]["plot_value"].dropna().values
            y.append(float(vals[0]) if len(vals) else np.nan)
        all_y.extend([v for v in y if pd.notna(v)])
        offset = (i - (n_models - 1) / 2.0) * width
        ax.bar(
            x + offset,
            y,
            width=width,
            color="white",
            edgecolor=SCHEME_COLOR.get(scheme, "black"),
            linewidth=1.2,
            hatch=SCHEME_HATCH.get(scheme, ""),
            label=SCHEME_LABEL.get(scheme, scheme),
        )

    ax.set_yscale("log")
    adjust_log_ylim(ax, all_y)
    ax.yaxis.set_major_locator(LogLocator(base=10.0, numticks=8))
    ax.yaxis.set_minor_formatter(NullFormatter())
    ax.set_xticks(x)
    ax.set_xticklabels(USER_LABELS)
    ax.set_xlabel("Number of users")
    ax.set_ylabel(ylabel)
    ax.set_title(title, fontsize=12)
    setup_grid(ax)
    ax.legend(
        loc="upper left",
        ncol=LEGEND_NCOL,
        fontsize=6.5,
        columnspacing=0.35,
        handlelength=1.05,
        handletextpad=0.35,
        labelspacing=0.22,
        borderpad=0.25,
        framealpha=0.86,
        borderaxespad=0.25,
    )
    fig.tight_layout()
    out_path = out_dir / filename
    fig.savefig(out_path, format="pdf")
    plt.close(fig)
    print(f"[INFO] wrote {out_path}")


def plot_six_panel(df: pd.DataFrame, out_dir: Path):
    fig, axes = plt.subplots(2, 3, figsize=(12.0, 6.3))
    axes = axes.flatten()
    for ax, metric in zip(axes, METRIC_INFO.keys()):
        title, _, ylabel = METRIC_INFO[metric]
        sub = df[df["metric"] == metric].copy()
        schemes_present = [s for s in SCHEME_ORDER if s in set(sub["scheme"])]
        x = np.arange(len(USERS))
        n_models = max(len(schemes_present), 1)
        width = min(0.12, 0.78 / n_models)
        all_y = []
        for i, scheme in enumerate(schemes_present):
            y = []
            for N in USERS:
                vals = sub[(sub["scheme"] == scheme) & (sub["N"] == N)]["plot_value"].dropna().values
                y.append(float(vals[0]) if len(vals) else np.nan)
            all_y.extend([v for v in y if pd.notna(v)])
            ax.bar(
                x + (i - (n_models - 1) / 2.0) * width,
                y,
                width=width,
                color="white",
                edgecolor=SCHEME_COLOR.get(scheme, "black"),
                linewidth=1.0,
                hatch=SCHEME_HATCH.get(scheme, ""),
                label=SCHEME_LABEL.get(scheme, scheme),
            )
        ax.set_yscale("log")
        adjust_log_ylim(ax, all_y)
        ax.set_xticks(x)
        ax.set_xticklabels(USER_LABELS)
        ax.set_title(title, fontsize=11)
        ax.set_xlabel("Number of users")
        ax.set_ylabel(ylabel)
        setup_grid(ax)

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=LEGEND_NCOL, framealpha=0.9)
    fig.tight_layout(rect=[0, 0, 1, 0.88])
    out_path = out_dir / "computation-six-panel.pdf"
    fig.savefig(out_path, format="pdf")
    plt.close(fig)
    print(f"[INFO] wrote {out_path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, default=Path("Figure-Exp-Data"), help="Directory containing clean CSV/XLSX files.")
    parser.add_argument("--csv", nargs="*", default=None, help="Explicit list of CSV/XLSX files. Overrides --data-dir scan.")
    parser.add_argument("--out", type=Path, default=Path("Figure-Exp"), help="Output directory for PDFs.")
    args = parser.parse_args()

    out_dir = args.out
    out_dir.mkdir(parents=True, exist_ok=True)

    paths = collect_files(args.data_dir, args.csv)
    print("[INFO] input files:")
    for p in paths:
        print("  -", p)

    df = load_data(paths)
    df = convert_ciphertext_sizes_to_kb(df)
    df = aggregate_duplicates(df)

    combined_path = out_dir / "combined_six_plot_data.csv"
    df.to_csv(combined_path, index=False, encoding="utf-8-sig")
    print(f"[INFO] wrote {combined_path}")

    print("\n[INFO] scheme/metric counts after normalization:")
    counts = df.groupby(["metric", "scheme"]).size().unstack(fill_value=0)
    print(counts.to_string())

    for metric in METRIC_INFO.keys():
        plot_metric(df, metric, out_dir)
    plot_six_panel(df, out_dir)

    print("\n[DONE] Every x-position should have one bar for each scheme present in the loaded clean data.")


if __name__ == "__main__":
    main()
