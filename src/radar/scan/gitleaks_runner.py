"""Discover a Gitleaks runtime (native binary -> Docker) and run a secrets scan.
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Literal

import platform
import tarfile
import urllib.request
import zipfile

from radar.scan.findings import Finding
from radar.scan.timeouts import scan_timeout

Runtime = Literal["native", "docker", "vendored"]
DOCKER_IMAGE = "zricethezav/gitleaks:latest"
GITLEAKS_VERSION = "8.18.2"

class GitleaksError(RuntimeError):
    pass

def _get_vendored_path() -> Path:
    base = Path.home() / ".radar" / "bin"
    base.mkdir(parents=True, exist_ok=True)
    exe = "gitleaks.exe" if platform.system() == "Windows" else "gitleaks"
    return base / exe

def _download_gitleaks(dest: Path):
    sys_name = platform.system().lower()
    machine = platform.machine().lower()
    
    # Map OS
    if sys_name == "windows":
        os_str = "windows"
        ext = "zip"
    elif sys_name == "darwin":
        os_str = "darwin"
        ext = "tar.gz"
    else:
        os_str = "linux"
        ext = "tar.gz"
        
    # Map Arch
    if machine in ["x86_64", "amd64"]:
        arch = "x64"
    elif machine in ["aarch64", "arm64"]:
        arch = "arm64"
    elif machine in ["x86", "i386", "i686"]:
        arch = "x32"
    else:
        arch = "x64" # fallback
        
    url = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/gitleaks_{GITLEAKS_VERSION}_{os_str}_{arch}.{ext}"
    
    import tempfile
    print(f"[dim]Downloading gitleaks {GITLEAKS_VERSION} for {os_str}-{arch}...[/]")
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{ext}") as tf:
            urllib.request.urlretrieve(url, tf.name)
            tmp_path = tf.name
            
        if ext == "zip":
            with zipfile.ZipFile(tmp_path, 'r') as z:
                z.extract("gitleaks.exe", dest.parent)
        else:
            with tarfile.open(tmp_path, 'r:gz') as t:
                # Gitleaks tar usually has 'gitleaks' at root
                t.extract("gitleaks", dest.parent)
                
        Path(tmp_path).unlink(missing_ok=True)
        dest.chmod(0o755)  # Make executable on Unix
    except Exception as exc:
        raise GitleaksError(f"Failed to download Gitleaks: {exc}")

def detect_runtime() -> Runtime | None:
    if shutil.which("gitleaks"):
        return "native"
        
    vendored_path = _get_vendored_path()
    if vendored_path.exists():
        return "vendored"
        
    # Auto-download first for zero-footprint seamless experience
    try:
        _download_gitleaks(vendored_path)
        return "vendored"
    except GitleaksError as e:
        print(f"[yellow]⚠ {e}[/]")
        
    # Fallback to docker if download fails
    if shutil.which("docker"):
        return "docker"

    return None

def run_gitleaks(target: Path, runtime: Runtime | None = None) -> list[Finding]:
    target = target.resolve()
    runtime = runtime or detect_runtime()
    if not runtime:
        # Graceful degradation if gitleaks is not available
        return []
        
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, dir=str(target.parent)) as tf:
        out_file = tf.name

    out_file_name = Path(out_file).name
    if runtime in ("native", "vendored"):
        exe_path = "gitleaks" if runtime == "native" else str(_get_vendored_path())
        argv = [exe_path, "detect", "--source", str(target), "-f", "json", "-r", out_file, "--no-git"]
    else:
        # docker: mount target.parent read-write so it can read target and write out_file
        # Note: /src will be target.parent, so --source is /src/<target.name>
        argv = [
            "docker", "run", "--rm",
            "-v", f"{target.parent.as_posix()}:/workspace",
            DOCKER_IMAGE,
            "detect", "--source", f"/workspace/{target.name}", "-f", "json", "-r", f"/workspace/{out_file_name}", "--no-git"
        ]

    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=scan_timeout(),
        )
    except subprocess.TimeoutExpired:
        Path(out_file).unlink(missing_ok=True)
        print(f"[dim yellow]⚠ gitleaks timed out after {scan_timeout()}s[/]")
        return []
    except OSError as exc:
        Path(out_file).unlink(missing_ok=True)
        print(f"[dim yellow]⚠ gitleaks failed: {exc}[/]")
        return []

    # gitleaks exits 1 if leaks found, 0 if clean.
    try:
        with open(out_file, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content and proc.returncode == 0:
                raw_leaks = []
            elif not content and proc.returncode != 0:
                # Execution failed (e.g. docker daemon offline)
                print(f"[dim yellow]⚠ gitleaks runner failed (exit {proc.returncode}):[/]")
                print(f"[dim yellow]  {proc.stderr.strip()}[/]")
                raw_leaks = []
            else:
                raw_leaks = json.loads(content)
    except Exception as exc:
        Path(out_file).unlink(missing_ok=True)
        return []
    
    Path(out_file).unlink(missing_ok=True)

    findings = []
    if raw_leaks:
        for leak in raw_leaks:
            desc = leak.get("Description", "Secret detected")
            if leak.get("Match"):
                desc += f" (Match: {leak['Match'][:30]}...)"
                
            file_path = leak.get("File", "?")
            # Ensure path is relative to target (like Semgrep)
            try:
                p = Path(file_path)
                if p.is_absolute():
                    file_path = p.relative_to(target).as_posix()
                else:
                    file_path = p.as_posix()
            except ValueError:
                pass # keep as is if not relative
                
            findings.append(
                Finding(
                    severity="ERROR",
                    path=file_path,
                    line=leak.get("StartLine", 0),
                    rule=f"gitleaks.{leak.get('RuleID', 'secret')}",
                    message=desc,
                    metadata={"owasp": "A02:2021-Cryptographic Failures"}
                )
            )
    
    return findings
