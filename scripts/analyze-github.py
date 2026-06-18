#!/usr/bin/env python3
"""
GitHub Repository Security & Impact Analyzer (Interactive)

Usage:
  python scripts/analyze-github.py
  python scripts/analyze-github.py --url https://github.com/org/repo
  python scripts/analyze-github.py --url <url> --branch feature/my-branch
  python scripts/analyze-github.py --url <url> --function validate_user

Prompts interactively for a GitHub URL, optional branch, and optional function name.
Runs a FULL analysis (OWASP scan + call graph + blast radius) and outputs ONE
unified HTML dashboard.

Repos are cached in `analysis_repos/<repo_name>/` — cloning is skipped if the repo
already exists there; only git fetch + checkout is performed to update.

Output:
  analysis_results/<repo>_unified_dashboard.html  — unified HTML dashboard:
      * OWASP Top 10 findings table (severity, location, rule)
      * Blast radius / impact graph (Mermaid diagram)
      * Scan history trend chart
      * AI triage columns (opt-in: set OPENAI_API_KEY)
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
    unified_html = out_dir / f"{repo_name}_unified_dashboard.html"

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

    # ─── STEP 2 — Unified Security Scan & Impact Analysis ────────────────────
    console.print("\n[bold blue]2.[/] Quet bao mat & Ve ban do anh huong (Unified Dashboard)...")
    
    # Build report command — --triage is opt-in (requires OPENAI_API_KEY)
    _triage_flag = ["--triage"] if os.environ.get("OPENAI_API_KEY") else []
    report_cmd = radar_base + ["report"] + _triage_flag + ["--out", str(unified_html)]
    
    if func_name:
        console.print(f"   [dim]Truy vet ham: {func_name}[/]")
        report_cmd += ["--function", func_name]
    elif branch:
        default_branch = "main"
        try:
            res = subprocess.run(
                ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
                cwd=repo_dir, capture_output=True, text=True, check=True
            )
            default_branch = res.stdout.strip().rsplit("/", 1)[-1]
        except Exception:
            pass

        console.print(f"   [dim]Diff nhanh '{branch}' vs default branch '{default_branch}'...[/]")
        try:
            run_cmd(["git", "fetch", "origin", default_branch], cwd=repo_dir, capture=True)
            diff_target = f"origin/{default_branch}...HEAD"
        except SystemExit:
            # Fallback to master if default_branch fetch failed or was incorrect
            if default_branch != "master":
                try:
                    run_cmd(["git", "fetch", "origin", "master"], cwd=repo_dir, capture=True)
                    diff_target = "origin/master...HEAD"
                except SystemExit:
                    diff_target = "HEAD~1"
            else:
                diff_target = "HEAD~1"
        report_cmd += ["--diff", diff_target]
    else:
        console.print("   [dim]Khong co branch/func — quet tong quan + auto blast radius tu findings...[/]")

    # Run unified report generator (which internally scans, triages, builds graph, and renders HTML)
    subprocess.run(report_cmd, cwd=repo_dir, check=False)

    # ─── Done ────────────────────────────────────────────────────────────────
    console.print(
        Panel(
            f"[bold green]Hoan tat![/]\n"
            f"Dashboard (unified): [cyan]{unified_html}[/]\n"
            f"Cache repo:          [cyan]{repo_dir}[/]",
            expand=False,
        )
    )


if __name__ == "__main__":
    main()
