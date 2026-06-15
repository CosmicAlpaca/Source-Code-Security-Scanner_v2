#!/usr/bin/env python3
"""
GitHub Repository Security & Impact Analyzer (Interactive)

Usage:
  python scripts/analyze-github.py

Prompts interactively for a GitHub URL, optional branch, and optional function name.
Then runs security scan + impact analysis and saves all results to `analysis_results/`.

Repos are cached in `analysis_repos/<repo_name>/` — cloning is skipped if the repo
already exists there; only git fetch + checkout is performed to update.

Output files:
  analysis_results/<repo>_semgrep_results.json   — OWASP / custom rule findings (JSON)
  analysis_results/<repo>_impact_graph.html      — interactive impact graph (HTML)
  analysis_results/<repo>_impact_graph.md        — Mermaid diagram (Markdown)
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# ── Encoding guard ────────────────────────────────────────────────────────────
# Force UTF-8 for this process AND every child subprocess (Semgrep, git, radar)
# so the script works on cp932 (JP), cp1252 (EU), cp936 (CN), etc.
os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure") and getattr(_s, "encoding", "").lower() != "utf-8":
        _s.reconfigure(encoding="utf-8", errors="replace")
# ─────────────────────────────────────────────────────────────────────────────


try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt

    console = Console()
except ImportError:
    print("Please install rich: pip install rich")
    sys.exit(1)


# ──────────────────────────── helpers ────────────────────────────


def run_cmd(cmd: list[str], cwd: Path | None = None, capture: bool = False) -> subprocess.CompletedProcess:
    """Run a command, raising sys.exit(1) on failure."""
    try:
        return subprocess.run(
            cmd,
            cwd=cwd,
            check=True,
            capture_output=capture,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Command failed:[/] {' '.join(cmd)}")
        if capture and e.stderr:
            console.print(f"[red]{e.stderr.strip()[:500]}[/]")
        sys.exit(1)


def ask(prompt: str, default: str = "") -> str:
    """Prompt user with a default value; return stripped response."""
    return Prompt.ask(prompt, default=default).strip()


# Validate user input before it reaches git/radar subprocess calls. List-form
# subprocess avoids shell injection, but an unchecked value starting with '-'
# could still be parsed as an option (argument injection into git clone/checkout).
_URL_RE = re.compile(r"^(https://|git@)[\w.@:/~-]+?(\.git)?$")
_REF_RE = re.compile(r"^\w[\w./-]*$")  # branch / function: no leading dash, safe chars


def validate_inputs(url: str, branch: str | None, func_name: str | None) -> None:
    """Reject inputs that could inject arguments into subprocess calls; exit on bad."""
    if not _URL_RE.match(url):
        console.print(f"[red]URL khong hop le:[/] {url}")
        sys.exit(1)
    for label, val in (("Nhanh", branch), ("Ten ham", func_name)):
        if val is not None and not _REF_RE.match(val):
            console.print(f"[red]{label} chua ky tu khong an toan:[/] {val}")
            sys.exit(1)


def impact_to_file(cmd: list[str], cwd: Path, out: Path, label: str, wrap=None) -> None:
    """Run an impact command; write `out` only if it produced output (no empty files).

    cmd carries user input (func_name/branch) already checked by validate_inputs();
    list-form subprocess, no shell.
    """
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)  # nosemgrep: dangerous-subprocess-use-tainted-env-args
    stdout = proc.stdout or ""
    if not stdout.strip():
        console.print(f"   [yellow]Khong co anh huong — bo qua {label}[/]")
        return
    out.write_text(wrap(stdout) if wrap else stdout, encoding="utf-8")
    console.print(f"   [green]{label}:[/] [cyan]{out}[/]")


# ──────────────────────────── main ────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze a GitHub repo for OWASP security issues and impact graph."
    )
    parser.add_argument("--url", default=None, help="GitHub repository URL (skip interactive prompt)")
    parser.add_argument("--branch", default=None, help="Branch to analyse (skip interactive prompt)")
    parser.add_argument("--function", dest="func_name", default=None, help="Function name for impact trace")
    args = parser.parse_args()

    interactive = args.url is None  # whether we prompt for all inputs

    console.print(
        Panel(
            "[bold green]Security Radar[/]  —  Phan tich ma nguon tu dong\n"
            "[dim]Clone + scan OWASP Top 10 + ve ban do anh huong (Impact Graph)[/]",
            expand=False,
        )
    )

    # ── gather inputs ──
    url: str = args.url or ask(
        "[bold cyan]GitHub URL[/] (vi du: https://github.com/OWASP/NodeGoat.git)"
    )
    if not url:
        console.print("[red]Khong co URL nao duoc nhap. Thoat.[/]")
        sys.exit(1)

    branch: str | None = args.branch
    func_name: str | None = args.func_name
    if interactive:
        branch_raw = ask(
            "[bold cyan]Nhanh can kiem tra diff[/] "
            "[dim](tuy chon — Enter de bo qua)[/]"
        )
        branch = branch_raw or None
        func_raw = ask(
            "[bold cyan]Ten ham can ve luong anh huong[/] "
            "[dim](tuy chon — Enter de bo qua)[/]"
        )
        func_name = func_raw or None

    validate_inputs(url, branch, func_name)

    # ── paths ──
    radar_base = ["radar"] if shutil.which("radar") else ["python", "-m", "radar"]
    repo_name = url.rstrip("/").split("/")[-1].removesuffix(".git")

    repos_cache = Path.cwd() / "analysis_repos"
    repos_cache.mkdir(exist_ok=True)
    repo_dir = repos_cache / repo_name

    out_dir = Path.cwd() / "analysis_results"
    out_dir.mkdir(exist_ok=True)
    scan_json   = out_dir / f"{repo_name}_semgrep_results.json"
    impact_html = out_dir / f"{repo_name}_impact_graph.html"
    impact_md   = out_dir / f"{repo_name}_impact_graph.md"

    console.print(f"\n[dim]Repo: [cyan]{repo_name}[/]  |  Branch: [cyan]{branch or '(default)'}[/]  |  Func: [cyan]{func_name or '(none)'}[/][/]")

    # ─── STEP 1 — Clone or reuse cache ───────────────────────────────────────
    if repo_dir.exists():
        console.print(
            f"\n[bold blue]1.[/] Repo [cyan]{repo_name}[/] da ton tai tai "
            f"[dim]{repo_dir}[/] — [green]bo qua buoc clone[/]."
        )
        if branch:
            console.print(f"   [dim]fetch --all + checkout {branch}...[/]")
            run_cmd(["git", "fetch", "--all"], cwd=repo_dir)
            run_cmd(["git", "checkout", branch], cwd=repo_dir)
        else:
            console.print("   [dim]git pull (nhanh hien tai)...[/]")
            subprocess.run(["git", "pull"], cwd=repo_dir, check=False)
    else:
        console.print(f"\n[bold blue]1.[/] Dang clone vao [cyan]{repo_dir}[/]...")
        run_cmd(["git", "clone", url, str(repo_dir)])
        if branch:
            console.print(f"   Checkout nhanh: [cyan]{branch}[/]")
            run_cmd(["git", "checkout", branch], cwd=repo_dir)

    # ─── STEP 2 — Security scan ──────────────────────────────────────────────
    console.print("\n[bold blue]2.[/] Quet bao mat (OWASP Top 10 + Custom Rules)...")

    # Display in terminal
    subprocess.run(radar_base + ["scan", "."], cwd=repo_dir, check=False)

    # Save JSON report
    with open(scan_json, "w", encoding="utf-8") as fh:
        subprocess.run(
            radar_base + ["scan", ".", "--format", "json"],
            cwd=repo_dir, stdout=fh, check=False,
        )
    console.print(f"   [green]Ket qua quet luu vao:[/] [cyan]{scan_json}[/]")

    # ─── STEP 3 — Impact analysis ────────────────────────────────────────────
    console.print("\n[bold blue]3.[/] Phan tich ban do anh huong (Impact Graph)...")

    if func_name:
        console.print(f"   [dim]Truy vet ham: {func_name}[/]")
        base = radar_base + ["impact", "--function", func_name, "--path", "."]
        # terminal tree (func_name validated by validate_inputs() above; no shell)
        subprocess.run(base, cwd=repo_dir, check=False)  # nosemgrep: dangerous-subprocess-use-tainted-env-args
        impact_to_file(base + ["--format", "html"], repo_dir, impact_html, "HTML")
        impact_to_file(
            base + ["--format", "mermaid"], repo_dir, impact_md, "Mermaid MD",
            wrap=lambda s: f"```mermaid\n{s}\n```",
        )

    elif branch:
        console.print(f"   [dim]Diff nhanh '{branch}' vs origin/main...[/]")
        # detect default branch
        try:
            run_cmd(["git", "fetch", "origin", "main"], cwd=repo_dir, capture=True)
            diff_target = "origin/main...HEAD"
        except SystemExit:
            diff_target = "HEAD~1"

        base = radar_base + ["impact", "--diff", diff_target, "--path", "."]
        subprocess.run(base, cwd=repo_dir, check=False)
        impact_to_file(base + ["--format", "html"], repo_dir, impact_html, "HTML")

    else:
        console.print("   [dim]Khong co branch/func — chi build graph tong quan...[/]")
        subprocess.run(radar_base + ["build", "."], cwd=repo_dir, check=False)
        console.print("   [dim](Xuat file HTML/MD khi chon --branch hoac --function)[/]")

    # ─── Done ────────────────────────────────────────────────────────────────
    console.print(
        Panel(
            f"[bold green]Hoan tat![/]\n"
            f"File phan tich: [cyan]{out_dir}[/]\n"
            f"Cache repo:     [cyan]{repo_dir}[/]",
            expand=False,
        )
    )


if __name__ == "__main__":
    main()
