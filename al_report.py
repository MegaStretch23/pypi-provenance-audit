"""attest-lock: package-level verdicts, the run loop, exit codes, table + summary."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from al_lock import LockedPackage, parse_uv_lock
from al_verify import FileResult, declared_repos, verify_file

EXIT_OK, EXIT_USAGE, EXIT_MISMATCH, EXIT_VERIFY_FAIL, EXIT_UNATTESTED = 0, 1, 2, 3, 4


@dataclass
class PackageResult:
    name: str
    version: str
    source: str
    files: list[FileResult] = field(default_factory=list)
    declared: list[str] = field(default_factory=list)
    expected: list[str] = field(default_factory=list)  # from --expect, overrides declared
    repos: list[str] = field(default_factory=list)  # distinct attested repos across files
    attested: int = 0
    total: int = 0
    verdict: str = ""  # MATCH | MISMATCH | NO-REPO-DECLARED | UNATTESTED | VERIFY-FAILED | SKIPPED | ERROR


def check_package(pkg: LockedPackage, fetcher, offline: bool, expect: dict[str, str],
                  max_files: int | None) -> PackageResult:
    res = PackageResult(pkg.name, pkg.version, pkg.source)
    if pkg.source != "pypi":
        res.verdict = "SKIPPED"
        return res
    files = pkg.files[:max_files] if max_files else pkg.files
    res.total = len(files)
    res.files = [verify_file(pkg.name, pkg.version, f, fetcher, offline) for f in files]
    status, body = fetcher.get(f"https://pypi.org/pypi/{pkg.name}/{pkg.version}/json")
    meta = json.loads(body) if status == 200 else None
    res.declared = sorted(declared_repos(meta))
    if pkg.name in expect:
        res.expected = [expect[pkg.name]]
    res.attested = sum(1 for f in res.files if f.status == "attested")
    res.repos = sorted({f.repo for f in res.files if f.status == "attested"})
    if any(f.status == "verify-failed" for f in res.files):
        res.verdict = "VERIFY-FAILED"
    elif res.attested == 0:
        res.verdict = "UNATTESTED" if all(f.status == "unattested" for f in res.files) else "ERROR"
    else:
        want = set(res.expected or res.declared)
        if not want:
            res.verdict = "NO-REPO-DECLARED"
        elif set(res.repos) <= want:
            res.verdict = "MATCH"
        else:
            res.verdict = "MISMATCH"
    return res


def run(lock: Path, fetcher, offline: bool, expect: dict[str, str], max_files: int | None,
        workers: int) -> list[PackageResult]:
    pkgs = parse_uv_lock(lock)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        return list(ex.map(lambda p: check_package(p, fetcher, offline, expect, max_files), pkgs))


def exit_code(results: list[PackageResult], require_attested: bool) -> int:
    verdicts = {r.verdict for r in results}
    if "VERIFY-FAILED" in verdicts:
        return EXIT_VERIFY_FAIL
    if "MISMATCH" in verdicts:
        return EXIT_MISMATCH
    if require_attested and ({"UNATTESTED", "ERROR"} & verdicts):
        return EXIT_UNATTESTED
    return EXIT_OK


def render_table(results: list[PackageResult]) -> str:
    rows = [("package", "version", "attested", "attested repo", "declared repo", "verdict")]
    for r in results:
        rows.append((
            r.name, r.version,
            "-" if r.verdict == "SKIPPED" else f"{r.attested}/{r.total}",
            ", ".join(r.repos) or "-",
            ", ".join(r.expected or r.declared) or "-",
            r.verdict,
        ))
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    lines = ["  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() for row in rows]
    lines.insert(1, "  ".join("-" * w for w in widths))
    return "\n".join(lines)


def summarize(results: list[PackageResult]) -> str:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    files = sum(r.total for r in results)
    att = sum(r.attested for r in results)
    return (f"{len(results)} packages, {att}/{files} files attested+verified; "
            + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
