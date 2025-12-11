"""Hash engine for computing and verifying file hashes."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime
from pathlib import Path
from typing import Iterable

from fim_agent.core.config import Config
from fim_agent.core.storage import Storage


def compute_file_hash(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _resolve(base: Path, candidate: Path) -> Path:
    """Resolve a candidate path relative to base when needed."""
    return candidate if candidate.is_absolute() else (base / candidate)


def build_baseline(directories: Iterable[Path], storage: Storage, config: Config) -> int:
    """
    Walk directories, compute file hashes, and store baseline records.

    Returns the number of files hashed.
    """
    total = 0
    timestamp = datetime.utcnow()

    for directory in directories:
        root = Path(directory).resolve()
        if not root.exists():
            continue

        exclude_dirs = {_resolve(root, Path(p)).resolve() for p in config.exclude_directories}
        exclude_exts = set(config.exclude_extensions)

        for current_root, dirs, files in os.walk(root, topdown=True):
            current_path = Path(current_root)

            # Prune excluded directories
            dirs[:] = [
                d
                for d in dirs
                if (current_path / d).resolve() not in exclude_dirs
            ]

            for filename in files:
                file_path = current_path / filename
                if file_path.suffix in exclude_exts:
                    continue
                try:
                    file_hash = compute_file_hash(file_path)
                except (OSError, PermissionError):
                    continue

                storage.upsert_file(str(file_path), file_hash, "baseline", timestamp)
                total += 1

    return total


__all__ = ["compute_file_hash", "build_baseline"]
