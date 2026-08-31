"""Resolve and verify immutable source checkouts used by installed Fusion tools."""
from __future__ import annotations

import json
import hashlib
import stat
import os
import subprocess
from pathlib import Path
from typing import Mapping

SOURCE_NAMES = ("fusion", "om", "mom", "nona", "omega")
MOUNT_ENV = "FUSION_SOURCE_MOUNT_ROOT"
MANIFEST_NAME = "closure-manifest.json"
BINDING_NAME = "source-binding.json"

IGNORED_RUNTIME_NAMES = frozenset({"__pycache__", ".DS_Store"})
IGNORED_RUNTIME_SUFFIXES = (".pyc", ".pyo")

class SourceBindingError(ValueError):
    """An installed source binding or selected checkout is invalid."""


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(("git", *args), cwd=root, text=True, capture_output=True)
    if completed.returncode:
        raise SourceBindingError(f"source_binding.git_failed:{root}:{completed.stderr.strip()}")
    return completed.stdout.strip()


def source_identity(root: Path) -> dict[str, str]:
    root = root.expanduser().resolve()
    if not root.is_dir() or root.is_symlink():
        raise SourceBindingError(f"source_binding.root_invalid:{root}")
    commit = _git(root, "rev-parse", "--verify", "HEAD^{commit}")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise SourceBindingError(f"source_binding.checkout_dirty:{root}")
    index = _git(root, "ls-files", "-v", "--stage")
    if any(not row.startswith("H ") for row in index.splitlines()):
        raise SourceBindingError(f"source_binding.hidden_index:{root}")
    sparse_name = _git(root, "rev-parse", "--git-path", "info/sparse-checkout")
    sparse = Path(sparse_name) if Path(sparse_name).is_absolute() else root / sparse_name
    if sparse.exists():
        raise SourceBindingError(f"source_binding.sparse_checkout:{root}")
    return {"path": str(root), "commit": commit, "tree": tree}


def closure_manifest(root: Path) -> dict[str, object]:
    """Describe every regular private-closure file except bindings and runtime cache noise."""
    root = root.resolve()
    entries: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix().encode()):
        relative_path = path.relative_to(root)
        relative = relative_path.as_posix()
        if relative in {BINDING_NAME, MANIFEST_NAME}:
            continue
        if any(part in IGNORED_RUNTIME_NAMES for part in relative_path.parts) or path.suffix in IGNORED_RUNTIME_SUFFIXES:
            continue
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or path.is_symlink():
            raise SourceBindingError(f"source_binding.closure_path_invalid:{relative}")
        entries.append({"path": relative, "mode": format(stat.S_IMODE(info.st_mode), "04o"),
                        "size": info.st_size,
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return {"schema": "suite.closure_manifest", "major": 1, "files": entries}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def write_binding(path: Path, roots: Mapping[str, Path]) -> None:
    root = path.parent
    manifest = closure_manifest(root)
    manifest_path = root / MANIFEST_NAME
    manifest_path.write_bytes(_canonical(manifest) + b"\n")
    manifest_path.chmod(0o444)
    binding = {"schema": "suite.source_binding", "major": 1,
               "closure_manifest_sha256": hashlib.sha256(_canonical(manifest)).hexdigest(),
               "sources": {name: source_identity(roots[name]) for name in SOURCE_NAMES}}
    path.write_bytes(_canonical(binding) + b"\n")
    path.chmod(0o444)


def verify_closure(root: Path, expected_digest: str) -> None:
    manifest_path = root / MANIFEST_NAME
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        raise SourceBindingError("source_binding.closure_manifest_unreadable") from exc
    if (not isinstance(expected_digest, str)
            or hashlib.sha256(_canonical(manifest)).hexdigest() != expected_digest
            or manifest != closure_manifest(root)):
        raise SourceBindingError("source_binding.closure_drift")
    for name in (BINDING_NAME, MANIFEST_NAME):
        path = root / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.is_symlink() or stat.S_IMODE(info.st_mode) != 0o444:
            raise SourceBindingError("source_binding.closure_mode_invalid")


def _load(path: Path) -> tuple[dict[str, dict[str, str]], str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        raise SourceBindingError("source_binding.unreadable") from exc
    fields = {"schema", "major", "closure_manifest_sha256", "sources"}
    if (not isinstance(value, dict) or set(value) != fields
            or value.get("schema") != "suite.source_binding" or value.get("major") != 1):
        raise SourceBindingError("source_binding.fields_invalid")
    sources = value.get("sources")
    digest = value.get("closure_manifest_sha256")
    if (not isinstance(sources, dict) or set(sources) != set(SOURCE_NAMES)
            or not isinstance(digest, str) or len(digest) != 64):
        raise SourceBindingError("source_binding.sources_invalid")
    result: dict[str, dict[str, str]] = {}
    for name in SOURCE_NAMES:
        source = sources[name]
        if (not isinstance(source, dict) or set(source) != {"path", "commit", "tree"}
                or any(not isinstance(item, str) or not item for item in source.values())):
            raise SourceBindingError("source_binding.source_invalid")
        result[name] = dict(source)
    return result, digest


def resolve_sources(private_root: Path, *, fusion_root: Path | None = None,
                    mount_root: Path | None = None) -> dict[str, Path]:
    """Resolve selected roots and prove each still equals its install-time identity."""
    private_root = private_root.resolve()
    binding_path = private_root / "source-binding.json"
    if not binding_path.is_file():
        if fusion_root is not None or mount_root is not None or os.environ.get(MOUNT_ENV):
            raise SourceBindingError("source_binding.override_without_binding")
        return {"fusion": private_root,
                "om": Path.home() / "Creations" / "OM",
                "mom": Path.home() / "Creations" / "Mom",
                "nona": Path.home() / "Creations" / "Nona",
                "omega": Path.home() / "Creations" / "Omega"}
    sources, manifest_digest = _load(binding_path)
    verify_closure(private_root, manifest_digest)
    env_mount = os.environ.get(MOUNT_ENV)
    if mount_root is not None and env_mount:
        raise SourceBindingError("source_binding.mount_ambiguous")
    selected_mount = mount_root or (Path(env_mount) if env_mount else None)
    if selected_mount is not None and fusion_root is not None:
        raise SourceBindingError("source_binding.override_ambiguous")
    if selected_mount is not None:
        base = selected_mount.expanduser().resolve()
        roots = {name: base / name / "repo" for name in SOURCE_NAMES}
    else:
        roots = {name: Path(sources[name]["path"]).expanduser().resolve()
                 for name in SOURCE_NAMES}
        if fusion_root is not None:
            roots["fusion"] = fusion_root.expanduser().resolve()
    for name in SOURCE_NAMES:
        observed = source_identity(roots[name])
        if any(observed[key] != sources[name][key] for key in ("commit", "tree")):
            raise SourceBindingError(f"source_binding.identity_mismatch:{name}")
    return roots
