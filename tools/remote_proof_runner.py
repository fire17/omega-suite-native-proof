#!/usr/bin/env python3
"""Prepare a private GitHub-hosted Darwin Intel observation run.

This is transport only: exact committed source blobs + tuple-bound runtime
closures in, unsigned ``clean_reproduce`` rows out. It cannot sign or promote.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    from supervisor.releases import canonical, load_product_runtime_closure, runtime_closure_cas_paths, validate_product_release_candidate  # noqa: E402
    from supervisor.validation import content_cid  # noqa: E402
    from tools.suite_control import configure_source_roots, load_compatibility_proposal, load_release_candidate_tuple  # noqa: E402
except ModuleNotFoundError:
    # Generated transport repositories intentionally carry only this verifier and encrypted input.
    def canonical(value: object) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8", "strict")

    def content_cid(value: Mapping[str, object]) -> str:
        return "sha256:" + hashlib.sha256(canonical({key: item for key, item in value.items() if key != "cid"})).hexdigest()

    load_product_runtime_closure = runtime_closure_cas_paths = validate_product_release_candidate = None
    configure_source_roots = load_compatibility_proposal = load_release_candidate_tuple = None

PRODUCTS = ("om", "mom", "nona", "omega")
DETAIL_SCHEMA = "suite.platform_observation"
PRODUCT_ROOTS: dict[str, Path] = {}
RUNTIME_CLOSURES = ROOT / ".deify" / "architecture" / "releases" / "runtime-closures"

TARGET = "darwin-x86_64"
RUNNER = "macos-15-intel"
WORKFLOW = "platform-proof.yml"
AUTHORITY = {"signed": False, "can_sign": False, "can_promote": False}
PUBLIC_SECRET = "OMEGA_TRANSFER_KEY"
OPENSSL = "/usr/bin/openssl"
SOURCES = ("fusion", "om", "mom", "nona", "omega")
PRODUCTS = ("om", "mom", "nona", "omega")
MAX_FILES, MAX_FILE, MAX_TOTAL = 200_000, 2 << 30, 8 << 30
CID = re.compile(r"sha256:[0-9a-f]{64}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
OID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
REF = re.compile(r"[0-9a-f]{40}\Z")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
ROW_FILES = ("environment.json", "lifecycle.json", "platform-proof.json", "transcript.json")


class RemoteProofError(ValueError):
    def __init__(self, code: str, detail: str = ""):
        self.code = code
        super().__init__(code + (f":{detail}" if detail else ""))


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def safe_path(raw: object, code: str = "remote.path_unsafe") -> str:
    if not isinstance(raw, str) or not raw or "\\" in raw or "\0" in raw:
        raise RemoteProofError(code)
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise RemoteProofError(code)
    return raw


def strict_json(data: bytes, code: str) -> object:
    def pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
        out: dict[str, object] = {}
        for key, value in rows:
            if key in out:
                raise RemoteProofError(code, f"duplicate:{key}")
            out[key] = value
        return out
    try:
        return json.loads(data.decode("utf-8", "strict"), object_pairs_hook=pairs,
                          parse_float=lambda _: (_ for _ in ()).throw(RemoteProofError(code)),
                          parse_constant=lambda _: (_ for _ in ()).throw(RemoteProofError(code)))
    except RemoteProofError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RemoteProofError(code) from exc


def git(repo: Path, *args: str, binary: bool = False) -> bytes | str:
    result = subprocess.run(("git", *args), cwd=repo, check=False, capture_output=True,
                            text=not binary, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, timeout=60)
    if result.returncode:
        raise RemoteProofError("remote.git_failed", str(repo))
    return result.stdout


def git_text(repo: Path, *args: str) -> str:
    out = git(repo, *args)
    assert isinstance(out, str)
    return out.strip()


def verify_checkout(repo: Path, commit: str, tree: str, branch: str | None = None,
                    *, require_clean: bool = True) -> None:
    if not OID.fullmatch(commit) or not OID.fullmatch(tree):
        raise RemoteProofError("remote.source_identity_invalid")
    if git_text(repo, "rev-parse", "HEAD") != commit or git_text(repo, "rev-parse", "HEAD^{tree}") != tree:
        raise RemoteProofError("remote.source_ref_mismatch", str(repo))
    if branch is not None and git_text(repo, "branch", "--show-current") != branch:
        raise RemoteProofError("remote.source_ref_mismatch", str(repo))
    if require_clean and git_text(repo, "status", "--porcelain=v1", "--untracked-files=all"):
        raise RemoteProofError("remote.source_dirty", str(repo))
    if git_text(repo, "rev-parse", "--is-shallow-repository") == "true":
        raise RemoteProofError("remote.source_shallow", str(repo))
    sparse = subprocess.run(("git", "config", "--bool", "--get", "core.sparseCheckout"), cwd=repo,
                            check=False, capture_output=True, text=True, timeout=30)
    if sparse.returncode not in (0, 1) or (sparse.returncode == 0 and sparse.stdout.strip() == "true"):
        raise RemoteProofError("remote.source_sparse", str(repo))
    index = git(repo, "ls-files", "-v", "-z", binary=True)
    assert isinstance(index, bytes)
    if any(len(row) > 1 and row[:1] in b"Ssh" for row in index.split(b"\0")):
        raise RemoteProofError("remote.source_hidden", str(repo))


def git_object_oid(kind: str, payload: bytes, width: int) -> str:
    framed = kind.encode("ascii") + b" " + str(len(payload)).encode("ascii") + b"\0" + payload
    if width == 40:
        return hashlib.sha1(framed).hexdigest()
    if width == 64:
        return hashlib.sha256(framed).hexdigest()
    raise RemoteProofError("remote.source_identity_invalid")


def source_entries(repo: Path, commit: str, name: str) -> list[tuple[str, int, bytes]]:
    listing = git(repo, "ls-tree", "-r", "-z", "--full-tree", commit, binary=True)
    assert isinstance(listing, bytes)
    out: list[tuple[str, int, bytes]] = []
    for row in filter(None, listing.split(b"\0")):
        try:
            meta, encoded = row.split(b"\t", 1)
            mode, kind, oid = meta.decode("ascii").split(" ")
            relative = safe_path(encoded.decode("utf-8", "strict"), "remote.source_path_unsafe")
        except (UnicodeError, ValueError) as exc:
            raise RemoteProofError("remote.source_tree_invalid") from exc
        if kind != "blob" or mode not in ("100644", "100755"):
            raise RemoteProofError("remote.source_symlink_refused", relative)
        body = git(repo, "cat-file", "blob", oid, binary=True)
        assert isinstance(body, bytes)
        if len(body) > MAX_FILE:
            raise RemoteProofError("remote.transfer_too_large")
        out.append((f"sources/{name}/repo/{relative}", 0o755 if mode == "100755" else 0o644, body))
    return out
def source_bundle(repo: Path, commit: str, name: str) -> tuple[str, int, bytes]:
    if git_text(repo, "rev-parse", "HEAD") != commit:
        raise RemoteProofError("remote.source_ref_mismatch", str(repo))
    body = git(repo, "bundle", "create", "-", "HEAD", binary=True)
    assert isinstance(body, bytes)
    if not body or len(body) > MAX_FILE:
        raise RemoteProofError("remote.transfer_too_large")
    return f"sources/{name}/repo.bundle", 0o644, body


def restore_source_bundles(root: Path, identities: Mapping[str, object]) -> None:
    for name in SOURCES:
        identity = identities.get(name)
        if not isinstance(identity, dict) or set(identity) != {"commit", "tree", "branch"}:
            raise RemoteProofError("remote.manifest_invalid")
        destination = root / "sources" / name / "repo"
        bundle = root / "sources" / name / "repo.bundle"
        if destination.exists() or destination.is_symlink() or not bundle.is_file() or bundle.is_symlink():
            raise RemoteProofError("remote.source_restore_invalid", name)
        result = subprocess.run(("git", "clone", "--quiet", "--no-local", str(bundle), str(destination)),
                                check=False, capture_output=True, timeout=180,
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        if result.returncode:
            raise RemoteProofError("remote.source_restore_invalid", name)
        commit, tree, branch = (str(identity[key]) for key in ("commit", "tree", "branch"))
        result = subprocess.run(("git", "checkout", "--quiet", "-B", branch, commit), cwd=destination,
                                check=False, capture_output=True, timeout=60,
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        if result.returncode:
            raise RemoteProofError("remote.source_restore_invalid", name)
        verify_checkout(destination, commit, tree, branch)


def make_tar(rows: Sequence[tuple[str, int, bytes]]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, mode, body in sorted(rows, key=lambda row: row[0].encode()):
            safe_path(name)
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(body), mode, 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(body))
    return stream.getvalue()


def read_tar(data: bytes) -> list[tuple[str, int, bytes]]:
    if not data or len(data) > MAX_TOTAL:
        raise RemoteProofError("remote.archive_size_invalid")
    rows: list[tuple[str, int, bytes]] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            members = archive.getmembers()
            if not members or len(members) > MAX_FILES:
                raise RemoteProofError("remote.archive_count_invalid")
            total = 0
            for member in members:
                name = safe_path(member.name, "remote.archive_path_unsafe")
                if (not member.isfile() or member.issym() or member.islnk() or member.mode not in (0o644, 0o755)
                        or member.uid or member.gid or member.mtime or member.uname or member.gname):
                    raise RemoteProofError("remote.archive_member_unsafe", name)
                handle = archive.extractfile(member)
                body = handle.read(MAX_FILE + 1) if handle else b""
                total += len(body)
                if len(body) != member.size or len(body) > MAX_FILE or total > MAX_TOTAL:
                    raise RemoteProofError("remote.archive_size_invalid")
                rows.append((name, member.mode, body))
    except RemoteProofError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise RemoteProofError("remote.archive_invalid") from exc
    if rows != sorted(rows, key=lambda row: row[0].encode()) or len({row[0] for row in rows}) != len(rows) or make_tar(rows) != data:
        raise RemoteProofError("remote.archive_not_canonical")
    return rows


def write_once(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
            raise RemoteProofError("remote.output_collision", str(path))
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def verify_transfer_bytes(data: bytes) -> dict[str, object]:
    rows = read_tar(data)
    by_name = {name: (mode, body) for name, mode, body in rows}
    if "transfer-manifest.json" not in by_name:
        raise RemoteProofError("remote.manifest_missing")
    manifest = strict_json(by_name["transfer-manifest.json"][1], "remote.manifest_invalid")
    fields = {"schema", "major", "cid", "candidate_tuple", "target", "sources", "files", "authority"}
    if (not isinstance(manifest, dict) or set(manifest) != fields or manifest.get("schema") != "suite.remote_native_input"
            or manifest.get("major") != 1 or manifest.get("target") != TARGET or manifest.get("authority") != AUTHORITY
            or manifest.get("cid") != content_cid(manifest) or not CID.fullmatch(str(manifest.get("candidate_tuple", "")))):
        raise RemoteProofError("remote.manifest_invalid")
    sources, files = manifest.get("sources"), manifest.get("files")
    if not isinstance(sources, dict) or set(sources) != set(SOURCES) or not isinstance(files, list):
        raise RemoteProofError("remote.manifest_invalid")
    for identity in sources.values():
        if (not isinstance(identity, dict) or set(identity) != {"commit", "tree", "branch"}
                or not OID.fullmatch(str(identity["commit"])) or not OID.fullmatch(str(identity["tree"]))
                or not isinstance(identity["branch"], str) or not identity["branch"]):
            raise RemoteProofError("remote.manifest_invalid")
    expected, previous = {"transfer-manifest.json"}, b""
    for row in files:
        if not isinstance(row, dict) or set(row) != {"path", "mode", "size", "sha256"}:
            raise RemoteProofError("remote.manifest_invalid")
        name = safe_path(row["path"])
        encoded = name.encode()
        observed = by_name.get(name)
        if encoded <= previous or name in expected or observed is None:
            raise RemoteProofError("remote.manifest_order_invalid")
        previous, expected = encoded, expected | {name}
        if row != {"path": name, "mode": format(observed[0], "04o"), "size": len(observed[1]),
                   "sha256": hashlib.sha256(observed[1]).hexdigest()}:
            raise RemoteProofError("remote.artifact_digest_mismatch", name)
    if set(by_name) != expected:
        raise RemoteProofError("remote.archive_extra_file")
    return manifest


def prepare(tuple_cid: str, output: Path) -> dict[str, object]:
    if not CID.fullmatch(tuple_cid):
        raise RemoteProofError("remote.tuple_unpinned")
    if load_release_candidate_tuple is None or validate_product_release_candidate is None or load_compatibility_proposal is None or runtime_closure_cas_paths is None or load_product_runtime_closure is None:
        raise RemoteProofError("remote.source_commands_unavailable")
    try:
        candidate_tuple = load_release_candidate_tuple(tuple_cid, verify_sources=False)
        products = candidate_tuple["products"]
        assert isinstance(products, dict)
        candidates: dict[str, dict[str, object]] = {}
        for product in PRODUCTS:
            value = strict_json(
                (PRODUCT_ROOTS[product] / ".deify/releases/candidates" / f"{products[product]}.json").read_bytes(),
                "remote.candidate_invalid",
            )
            candidates[product] = validate_product_release_candidate(value)
        proposal = load_compatibility_proposal(
            str(candidate_tuple["compatibility_proposal"]), expected_products=products,
            verify_closures=True,
        )
        closure_maps = proposal["runtime_closures"]
        assert isinstance(closure_maps, dict)
    except Exception as exc:
        raise RemoteProofError("remote.tuple_invalid", str(exc)) from exc
    supervisor = candidate_tuple["supervisor"]
    assert isinstance(supervisor, dict)
    identities = {"fusion": {"commit": str(supervisor["commit"]), "tree": str(supervisor["tree"]),
                             "branch": git_text(ROOT, "branch", "--show-current")}}
    roots = {"fusion": ROOT, **PRODUCT_ROOTS}
    rows: list[tuple[str, int, bytes]] = []
    for name in SOURCES:
        if name != "fusion":
            vcs = candidates[name]["vcs"]
            assert isinstance(vcs, dict)
            identities[name] = {key: str(vcs[key]) for key in ("commit", "tree", "branch")}
        verify_checkout(roots[name], identities[name]["commit"], identities[name]["tree"],
                        identities[name]["branch"], require_clean=False)
        rows.append(source_bundle(roots[name], identities[name]["commit"], name))
    for product in PRODUCTS:
        platform_closures = closure_maps[product]
        assert isinstance(platform_closures, dict)
        if TARGET not in platform_closures:
            continue
        closure_cid = str(platform_closures[TARGET])
        manifest_path, archive_path = runtime_closure_cas_paths(RUNTIME_CLOSURES.resolve(), product, closure_cid)
        _closure, manifest_bytes, archive_bytes = load_product_runtime_closure(
            manifest_path, archive_path, candidate=candidates[product], expected_root=RUNTIME_CLOSURES.resolve(),
        )
        rows.extend(((f"runtime-closures/{product}/{manifest_path.name}", 0o644, manifest_bytes),
                     (f"runtime-closures/packages/{product}/{archive_path.name}", 0o644, archive_bytes)))
    files = [{"path": name, "mode": format(mode, "04o"), "size": len(body),
              "sha256": hashlib.sha256(body).hexdigest()}
             for name, mode, body in sorted(rows, key=lambda row: row[0].encode())]
    if len(files) > MAX_FILES or sum(int(row["size"]) for row in files) > MAX_TOTAL:
        raise RemoteProofError("remote.transfer_too_large")
    manifest: dict[str, object] = {"schema": "suite.remote_native_input", "major": 1,
        "candidate_tuple": tuple_cid, "target": TARGET, "sources": identities,
        "files": files, "authority": AUTHORITY}
    manifest["cid"] = content_cid(manifest)
    rows.append(("transfer-manifest.json", 0o644, canonical(manifest) + b"\n"))
    data = make_tar(rows)
    verify_transfer_bytes(data)
    output = output.resolve()
    if output.suffix != ".tar" or output == ROOT or ROOT in output.parents:
        raise RemoteProofError("remote.output_path_invalid")
    write_once(output, data)
    write_once(output.with_suffix(".tar.sha256"), (hashlib.sha256(data).hexdigest() + "  " + output.name + "\n").encode())
    return {"candidate_tuple": tuple_cid, "input_cid": manifest["cid"], "archive": str(output),
            "archive_sha256": hashlib.sha256(data).hexdigest(), "archive_size": len(data)}


def encrypt_transfer(data: bytes, key: str) -> bytes:
    """Encrypt a transfer for a public transport repository without putting key bytes in argv."""
    if not re.fullmatch(r"[0-9a-f]{64}", key):
        raise RemoteProofError("remote.encryption_key_invalid")
    env = {"OMEGA_TRANSFER_KEY": key, "PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    command = (OPENSSL, "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "200000",
               "-salt", "-md", "sha256", "-pass", "env:OMEGA_TRANSFER_KEY")
    encrypted = subprocess.run(command, input=data, check=False, capture_output=True,
                               env=env, timeout=120)
    if encrypted.returncode or not encrypted.stdout or encrypted.stderr:
        raise RemoteProofError("remote.encryption_failed")
    decrypt_command = (OPENSSL, "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000",
                       "-salt", "-md", "sha256", "-pass", "env:OMEGA_TRANSFER_KEY")
    decrypted = subprocess.run(decrypt_command, input=encrypted.stdout,
                               check=False, capture_output=True, env=env, timeout=120)
    if decrypted.returncode or decrypted.stdout != data or decrypted.stderr:
        raise RemoteProofError("remote.encryption_roundtrip_failed")
    return encrypted.stdout


def verify_transfer(path: Path, extract: Path | None = None) -> dict[str, object]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RemoteProofError("remote.transfer_missing") from exc
    manifest = verify_transfer_bytes(data)
    if extract:
        extract = extract.resolve()
        if extract.exists() or extract.is_symlink():
            raise RemoteProofError("remote.extract_exists")
        extract.mkdir(mode=0o700, parents=True)
        try:
            for name, mode, body in read_tar(data):
                destination = extract.joinpath(*PurePosixPath(name).parts)
                write_once(destination, body, mode)
            sources = manifest.get("sources")
            assert isinstance(sources, dict)
            restore_source_bundles(extract, sources)
        except BaseException:
            shutil.rmtree(extract, ignore_errors=True)
            raise
    return {"candidate_tuple": manifest["candidate_tuple"], "input_cid": manifest["cid"],
            "archive_sha256": hashlib.sha256(data).hexdigest(), "extracted_to": str(extract) if extract else None}


def assert_runner() -> dict[str, object]:
    observed_os, observed_arch = platform.system(), platform.machine()
    if observed_os != "Darwin" or observed_arch != "x86_64":
        raise RemoteProofError("remote.runner_arch_mismatch", f"{observed_os}:{observed_arch}")
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or os.environ.get("RUNNER_OS") != "macOS" or os.environ.get("RUNNER_ARCH") != "X64":
        raise RemoteProofError("remote.runner_metadata_mismatch")
    for argv in (("/usr/sbin/sysctl", "-in", "sysctl.proc_translated"), ("/usr/sbin/sysctl", "-n", "hw.optional.arm64")):
        result = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip() == "1":
            raise RemoteProofError("remote.runner_translated")
    return {"target": TARGET, "runner_label": RUNNER, "observed_os": observed_os,
            "observed_arch": observed_arch, "translated": False}


WORKFLOW_TEXT = """name: Omega private native Darwin Intel observation
on:
  workflow_dispatch:
    inputs:
      tuple: {required: true, type: string}
      source_path: {required: true, type: string}
      source_sha256: {required: true, type: string}
permissions: {contents: read}
jobs:
  native-intel:
    runs-on: macos-15-intel
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
        with: {persist-credentials: false, lfs: true}
      - name: Verify immutable input and native Intel boundary
        env: {SOURCE_PATH: "${{ inputs.source_path }}", SOURCE_SHA256: "${{ inputs.source_sha256 }}"}
        run: |
          set -euo pipefail
          [[ "$SOURCE_PATH" =~ ^input/transfer-[0-9a-f]{64}\\.tar$ ]]
          [[ "$SOURCE_SHA256" =~ ^[0-9a-f]{64}$ ]]
          echo "$SOURCE_SHA256  $SOURCE_PATH" | shasum -a 256 -c -
          python3 tools/remote_proof_runner.py verify-transfer --archive "$SOURCE_PATH" --extract "$RUNNER_TEMP/export"
          python3 tools/remote_proof_runner.py assert-runner
      - name: Install exact Fusion closure
        run: |
          set -euo pipefail
          python3 "$RUNNER_TEMP/export/sources/fusion/repo/tools/install_suite_control.py" --prefix "$RUNNER_TEMP/installed" --source-root "$RUNNER_TEMP/export/sources/fusion/repo" --om-root "$RUNNER_TEMP/export/sources/om/repo" --mom-root "$RUNNER_TEMP/export/sources/mom/repo" --nona-root "$RUNNER_TEMP/export/sources/nona/repo" --omega-root "$RUNNER_TEMP/export/sources/omega/repo"
      - name: Run offline tuple-bound observation
        env: {FUSION_SOURCE_MOUNT_ROOT: "${{ runner.temp }}/export/sources"}
        run: |
          set -euo pipefail
          python3 "$RUNNER_TEMP/installed/libexec/fusion/tools/clean_reproduce.py" --tuple "${{ inputs.tuple }}" --platform darwin-x86_64 --runtime-closure-root "$RUNNER_TEMP/export/runtime-closures" --output "$RUNNER_TEMP/observation"
      - name: Verify readback
        run: |
          set -euo pipefail
          python3 tools/remote_proof_runner.py verify-readback --root "$RUNNER_TEMP/observation" --tuple "${{ inputs.tuple }}" --repo "$GITHUB_REPOSITORY" --workflow-ref "$GITHUB_SHA" --run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT" --transfer-sha256 "${{ inputs.source_sha256 }}" --output "$RUNNER_TEMP/receipt.json"
      - uses: actions/upload-artifact@65462800fd760344b1a7b4382951275a0abb4808
        with:
          name: "omega-native-intel-observation-${{ inputs.source_sha256 }}"
          path: |
            ${{ runner.temp }}/observation
            ${{ runner.temp }}/receipt.json
          if-no-files-found: error
          retention-days: 30
          compression-level: 0
"""

PUBLIC_WORKFLOW_TEXT = WORKFLOW_TEXT.replace(
    "Omega private native Darwin Intel observation",
    "Omega encrypted native Darwin Intel observation",
).replace(
    'env: {SOURCE_PATH: "${{ inputs.source_path }}", SOURCE_SHA256: "${{ inputs.source_sha256 }}"}',
    'env: {SOURCE_PATH: "${{ inputs.source_path }}", SOURCE_SHA256: "${{ inputs.source_sha256 }}", OMEGA_TRANSFER_KEY: "${{ secrets.OMEGA_TRANSFER_KEY }}"}',
).replace(
    'echo "$SOURCE_SHA256  $SOURCE_PATH" | shasum -a 256 -c -\n          python3 tools/remote_proof_runner.py verify-transfer --archive "$SOURCE_PATH" --extract "$RUNNER_TEMP/export"',
    'echo "$SOURCE_SHA256  $SOURCE_PATH" | shasum -a 256 -c -\n          test -n "$OMEGA_TRANSFER_KEY"\n          openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -salt -md sha256 -pass env:OMEGA_TRANSFER_KEY -in "$SOURCE_PATH" -out "$RUNNER_TEMP/transfer.tar"\n          python3 tools/remote_proof_runner.py verify-transfer --archive "$RUNNER_TEMP/transfer.tar" --extract "$RUNNER_TEMP/export"',
)


def prepare_repo(transfer: Path, output: Path) -> dict[str, object]:
    verified = verify_transfer(transfer)
    transfer_sha = str(verified["archive_sha256"])
    output = output.resolve()
    if output.exists() or output.is_symlink():
        raise RemoteProofError("remote.repo_output_exists")
    workflow = output / ".github/workflows" / WORKFLOW
    target = output / "input" / f"transfer-{transfer_sha}.tar"
    write_once(workflow, WORKFLOW_TEXT.encode())
    write_once(target, transfer.read_bytes())
    write_once(target.with_suffix(".tar.sha256"), (transfer_sha + "  " + target.name + "\n").encode())
    write_once(output / "tools/remote_proof_runner.py", Path(__file__).read_bytes(), 0o755)
    return {"output": str(output), "workflow": str(workflow.relative_to(output)),
            "source_path": str(target.relative_to(output)), "source_sha256": transfer_sha,
            "candidate_tuple": verified["candidate_tuple"], "runner_label": RUNNER}


def prepare_public_repo(transfer: Path, output: Path, key: str | None = None) -> dict[str, object]:
    data = transfer.read_bytes()
    verified = verify_transfer_bytes(data)
    key = key or secrets.token_hex(32)
    encrypted = encrypt_transfer(data, key)
    transfer_sha = hashlib.sha256(encrypted).hexdigest()
    output = output.resolve()
    if output.exists() or output.is_symlink():
        raise RemoteProofError("remote.repo_output_exists")
    workflow = output / ".github/workflows" / WORKFLOW
    target = output / "input" / f"transfer-{transfer_sha}.tar"
    write_once(workflow, PUBLIC_WORKFLOW_TEXT.encode())
    write_once(target, encrypted)
    write_once(target.with_suffix(".tar.sha256"), (transfer_sha + "  " + target.name + "\n").encode())
    write_once(output / "tools/remote_proof_runner.py", Path(__file__).read_bytes(), 0o755)
    return {"output": str(output), "workflow": str(workflow.relative_to(output)),
            "source_path": str(target.relative_to(output)), "source_sha256": transfer_sha,
            "candidate_tuple": verified["candidate_tuple"], "runner_label": RUNNER,
            "secret_name": PUBLIC_SECRET, "secret_value": key, "authority": AUTHORITY}


def validate_repo(repo: str) -> str:
    if not REPO.fullmatch(repo) or repo.startswith(".") or "/." in repo:
        raise RemoteProofError("remote.repo_invalid")
    return repo


def private_repo(repo: str) -> None:
    result = subprocess.run(("gh", "repo", "view", validate_repo(repo), "--json", "nameWithOwner,visibility,isPrivate"),
                            check=False, capture_output=True, timeout=120)
    value = strict_json(result.stdout, "remote.repo_metadata_invalid") if not result.returncode else None
    if not isinstance(value, dict) or value.get("nameWithOwner") != repo or value.get("visibility") != "PRIVATE" or value.get("isPrivate") is not True:
        raise RemoteProofError("remote.repo_public_refused")


def public_repo(repo: str) -> None:
    result = subprocess.run(("gh", "repo", "view", validate_repo(repo), "--json", "nameWithOwner,visibility,isPrivate"),
                            check=False, capture_output=True, timeout=120)
    value = strict_json(result.stdout, "remote.repo_metadata_invalid") if not result.returncode else None
    if not isinstance(value, dict) or value.get("nameWithOwner") != repo or value.get("visibility") != "PUBLIC" or value.get("isPrivate") is not False:
        raise RemoteProofError("remote.repo_private_refused")


def dispatch_command(repo: str, ref: str, tuple_cid: str, source_path: str, source_sha: str) -> list[str]:
    validate_repo(repo)
    if not REF.fullmatch(ref):
        raise RemoteProofError("remote.ref_mutable")
    if not CID.fullmatch(tuple_cid):
        raise RemoteProofError("remote.tuple_unpinned")
    if not SHA.fullmatch(source_sha) or source_path != f"input/transfer-{source_sha}.tar":
        raise RemoteProofError("remote.artifact_digest_invalid")
    fields = {"source_path": source_path, "source_sha256": source_sha, "tuple": tuple_cid}
    command = ["gh", "workflow", "run", WORKFLOW, "--repo", repo, "--ref", ref]
    for key in sorted(fields):
        command.extend(("--raw-field", f"{key}={fields[key]}"))
    return command


def read_regular(path: Path, root: Path) -> bytes:
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
        info = path.lstat()
    except (OSError, ValueError) as exc:
        raise RemoteProofError("remote.readback_path_invalid") from exc
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_nlink != 1 or not 0 < info.st_size <= 512 << 20:
        raise RemoteProofError("remote.readback_path_invalid")
    return path.read_bytes()


def verify_row(row: Path, tuple_cid: str, product: str) -> dict[str, object]:
    children = list(row.iterdir()) if row.is_dir() and not row.is_symlink() else []
    observations = [path for path in children if CID.fullmatch(path.stem) and path.suffix == ".json"]
    if len(observations) != 1 or {path.name for path in children} != {*ROW_FILES, observations[0].name}:
        raise RemoteProofError("remote.row_file_set_invalid")
    payloads = {name: read_regular(row / name, row) for name in ROW_FILES}
    observation = strict_json(read_regular(observations[0], row), "remote.observation_invalid")
    detail = strict_json(payloads["platform-proof.json"], "remote.detail_invalid")
    environment = strict_json(payloads["environment.json"], "remote.environment_invalid")
    expected = [{"path": name, "digest": digest(payloads[name]), "size": len(payloads[name])} for name in sorted(ROW_FILES)]
    if (not isinstance(observation, dict) or observation.get("cid") != content_cid(observation)
            or observation.get("cid") != observations[0].stem or observation.get("candidate_tuple") != tuple_cid
            or observation.get("platform") != TARGET or observation.get("status") != "pass"
            or observation.get("authority") != AUTHORITY or observation.get("artifacts") != expected):
        raise RemoteProofError("remote.observation_invalid")
    if (not isinstance(detail, dict) or detail.get("schema") != DETAIL_SCHEMA
            or detail.get("candidate_tuple") != tuple_cid or detail.get("product") != product
            or detail.get("platform") != TARGET or detail.get("status") != "pass" or detail.get("execution_boundary") != "native"):
        raise RemoteProofError("remote.detail_invalid")
    provenance = detail.get("architecture_provenance")
    commands = environment.get("commands") if isinstance(environment, dict) else None
    argv = commands[0].get("argv") if isinstance(commands, list) and commands and isinstance(commands[0], dict) else None
    capture = payloads["transcript.json"]  # Raw transcript remains digest-bound by the observation.
    if (not isinstance(provenance, dict) or provenance.get("execution_boundary") != "native"
            or provenance.get("observed_os") != "Darwin" or provenance.get("observed_arch") != "x86_64"
            or provenance.get("translated") is not False or not isinstance(environment, dict)
            or environment.get("cid") != content_cid(environment)
            or provenance.get("environment_evidence_cid") != environment.get("cid")
            or not isinstance(commands, list) or not commands or not isinstance(argv, list)
            or not capture):
        raise RemoteProofError("remote.runner_arch_mismatch")

def verify_readback(root: Path, *, tuple_cid: str, repo: str, workflow_ref: str, run_id: str,
                    run_attempt: int, transfer_sha256: str, output: Path | None = None) -> dict[str, object]:
    validate_repo(repo)
    if not CID.fullmatch(tuple_cid) or not REF.fullmatch(workflow_ref) or not RUN_ID.fullmatch(run_id):
        raise RemoteProofError("remote.readback_identity_invalid")
    if run_attempt < 1 or not SHA.fullmatch(transfer_sha256):
        raise RemoteProofError("remote.readback_identity_invalid")
    rows = [verify_row(root / "VAL-RELEASE" / product / TARGET, tuple_cid, product) for product in PRODUCTS]
    receipt: dict[str, object] = {"schema": "suite.remote_native_observation_receipt", "major": 1,
        "candidate_tuple": tuple_cid, "target": TARGET, "repository": repo, "workflow_ref": workflow_ref,
        "run_id": run_id, "run_attempt": run_attempt, "transfer_sha256": transfer_sha256,
        "runner_label": RUNNER, "rows": rows, "authority": AUTHORITY,
        "limitations": ["unsigned observation transport", "not platform proof", "cannot promote"]}
    receipt["cid"] = content_cid(receipt)
    if output:
        write_once(output.resolve(), canonical(receipt) + b"\n")
    return receipt


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="remote-proof-runner")
    result.add_argument("--source-root", type=Path)
    commands = result.add_subparsers(dest="command", required=True)
    one = commands.add_parser("prepare"); one.add_argument("--tuple", required=True); one.add_argument("--output", type=Path, required=True)
    one = commands.add_parser("verify-transfer"); one.add_argument("--archive", type=Path, required=True); one.add_argument("--extract", type=Path)
    commands.add_parser("assert-runner")
    one = commands.add_parser("prepare-repo"); one.add_argument("--transfer", type=Path, required=True); one.add_argument("--output", type=Path, required=True)
    one = commands.add_parser("prepare-public-repo"); one.add_argument("--transfer", type=Path, required=True); one.add_argument("--output", type=Path, required=True); one.add_argument("--key")
    one = commands.add_parser("dispatch"); one.add_argument("--repo", required=True); one.add_argument("--ref", required=True); one.add_argument("--tuple", required=True); one.add_argument("--source-path", required=True); one.add_argument("--source-sha256", required=True); one.add_argument("--public", action="store_true"); one.add_argument("--dry-run", action="store_true")
    one = commands.add_parser("verify-readback"); one.add_argument("--root", type=Path, required=True); one.add_argument("--tuple", required=True); one.add_argument("--repo", required=True); one.add_argument("--workflow-ref", required=True); one.add_argument("--run-id", required=True); one.add_argument("--run-attempt", type=int, required=True); one.add_argument("--transfer-sha256", required=True); one.add_argument("--output", type=Path)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command in {"prepare", "prepare-repo", "prepare-public-repo"}:
            if configure_source_roots is None:
                raise RemoteProofError("remote.source_commands_unavailable")
            roots = configure_source_roots(args.source_root)
            global ROOT, PRODUCT_ROOTS, RUNTIME_CLOSURES
            ROOT = roots["fusion"]
            PRODUCT_ROOTS = {name: roots[name] for name in PRODUCTS}
            RUNTIME_CLOSURES = ROOT / ".deify" / "architecture" / "releases" / "runtime-closures"
        if args.command == "prepare": result = prepare(args.tuple, args.output)
        elif args.command == "verify-transfer": result = verify_transfer(args.archive, args.extract)
        elif args.command == "assert-runner": result = assert_runner()
        elif args.command == "prepare-repo": result = prepare_repo(args.transfer, args.output)
        elif args.command == "prepare-public-repo": result = prepare_public_repo(args.transfer, args.output, args.key)
        elif args.command == "dispatch":
            command = dispatch_command(args.repo, args.ref, args.tuple, args.source_path, args.source_sha256)
            authority = AUTHORITY
            if args.dry_run:
                result = {"command": command, "authority": authority, "repository_visibility": "public" if args.public else "private"}
            else:
                (public_repo if args.public else private_repo)(args.repo)
                completed = subprocess.run(command, check=False, capture_output=True, timeout=120)
                if completed.returncode: raise RemoteProofError("remote.dispatch_failed")
                result = {"command": command, "runner_label": RUNNER, "authority": authority,
                          "repository_visibility": "public" if args.public else "private"}
        elif args.command == "verify-readback": result = verify_readback(args.root, tuple_cid=args.tuple, repo=args.repo, workflow_ref=args.workflow_ref, run_id=args.run_id, run_attempt=args.run_attempt, transfer_sha256=args.transfer_sha256, output=args.output)
        else: raise RemoteProofError("remote.command_invalid")
    except Exception as exc:
        code = exc.code if isinstance(exc, RemoteProofError) else "remote.operation_failed"
        print(json.dumps({"ok": False, "error_code": code, "detail": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps({"ok": True, "result": result}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
