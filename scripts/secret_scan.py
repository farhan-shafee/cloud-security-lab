"""Run Gitleaks on history and nonignored source files.

Subprocesses use fixed argv and resolved trusted developer tools, without a shell.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess  # nosec B404
import tempfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitleaks", default="gitleaks", help="Path to trusted Gitleaks binary")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    binary = shutil.which(args.gitleaks)
    git = shutil.which("git")
    if not binary or not git:
        parser.error("Install Git and the checksum-verified Gitleaks binary")
    history = subprocess.run(  # nosec B603
        [binary, "git", str(root), "--redact", "--no-banner"], check=False
    )
    if history.returncode:
        return history.returncode
    inventory = subprocess.run(  # nosec B603
        [git, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        capture_output=True,
        check=True,
    )
    files = inventory.stdout.decode("utf-8").split("\0")
    with tempfile.TemporaryDirectory(prefix="cloud-lab-secret-scan-") as directory:
        destination = Path(directory)
        for name in filter(None, files):
            source = root / name
            if not source.exists():
                continue  # Deleted tracked files remain covered by the history scan.
            if source.is_symlink() or not source.resolve().is_relative_to(root):
                raise ValueError(f"Refusing to copy out-of-repository path: {name}")
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        return subprocess.run(  # nosec B603
            [binary, "dir", str(destination), "--redact", "--no-banner"], check=False
        ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
