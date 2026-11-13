# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "sigstore>=3.6,<5",
#   "pypi-attestations>=0.0.20,<0.1",
# ]
# ///
"""attest-lock: verify PyPI attestations for every package pinned in a uv.lock.

For each registry package in the lock, every pinned file (sdist + wheels) is
looked up on PyPI's integrity endpoint.  When a provenance document exists, its
Sigstore bundle is verified with the sigstore library against (a) the publisher
identity PyPI recorded (GitHub/GitLab repo + workflow) and (b) the sha256 hash
that uv.lock pins for that file.  The repo named in the signing certificate is
then compared with the repo the project declares in its PyPI metadata.

Exit codes: 0 ok · 2 repo mismatch · 3 attestation present but fails to verify
· 4 unattested package with --require-attested · 1 usage/lock error.

Modules (same directory): al_lock (uv.lock parser + fetchers), al_verify (per-file
Sigstore verification), al_report (verdicts, exit codes, table), al_selfcheck.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict
from pathlib import Path

from al_lock import FixtureFetcher, HttpFetcher
from al_report import EXIT_USAGE, exit_code, render_table, run, summarize
from al_verify import _REPO_RE, normalize_repo


def parse_expect(items: list[str]) -> dict[str, str] | None:
    """--expect PKG=host/owner/repo -> {normalized-name: normalized-repo}; None on a malformed item."""
    expect: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            print(f"error: --expect wants PKG=host/owner/repo, got {item!r}", file=sys.stderr)
            return None
        k, v = item.split("=", 1)
        m = _REPO_RE.search(v if "://" in v else "https://" + v)
        expect[k.strip().lower().replace("_", "-")] = normalize_repo(*m.groups()) if m else v.strip().lower()
    return expect


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass
    ap = argparse.ArgumentParser(prog="attest-lock", description=__doc__.split("\n\n")[0])
    ap.add_argument("--lock", default="uv.lock", help="path to uv.lock (default ./uv.lock)")
    ap.add_argument("--offline", action="store_true", help="verify against the embedded Sigstore trust root, no TUF refresh")
    ap.add_argument("--fixtures", metavar="DIR", help="serve PyPI responses from DIR/index.json instead of the network")
    ap.add_argument("--expect", action="append", default=[], metavar="PKG=host/owner/repo",
                    help="expected repo for a package (overrides its declared metadata)")
    ap.add_argument("--require-attested", action="store_true", help="exit 4 if any package has no attestation at all")
    ap.add_argument("--max-files", type=int, default=None, help="only check the first N files per package (sdist first)")
    ap.add_argument("--workers", type=int, default=6, help="parallel packages (default 6)")
    ap.add_argument("--json", action="store_true", help="print JSON instead of the table")
    ap.add_argument("--out", metavar="FILE", help="also write the JSON report to FILE")
    ap.add_argument("--selfcheck", action="store_true", help="offline end-to-end check on the saved fixtures")
    a = ap.parse_args(argv)
    if a.selfcheck:
        from al_selfcheck import selfcheck
        return selfcheck()

    lock = Path(a.lock)
    if not lock.is_file():
        print(f"error: lock file not found: {lock}", file=sys.stderr)
        return EXIT_USAGE
    expect = parse_expect(a.expect)
    if expect is None:
        return EXIT_USAGE
    fetcher = FixtureFetcher(Path(a.fixtures)) if a.fixtures else HttpFetcher()
    if a.offline:  # sigstore logs "TUF repository is loaded in offline mode" once per verify
        logging.getLogger("sigstore").setLevel(logging.ERROR)

    results = run(lock, fetcher, a.offline, expect, a.max_files, a.workers)
    code = exit_code(results, a.require_attested)
    report = {"lock": lock.as_posix(), "offline": a.offline, "exit_code": code, "summary": summarize(results),
              "packages": [asdict(r) for r in results]}
    if a.out:
        Path(a.out).write_text(json.dumps(report, indent=1), encoding="utf-8")
    if a.json:
        print(json.dumps(report, indent=1))
    else:
        print(render_table(results))
        print()
        print(report["summary"])
        print(f"exit {code}")
    return code


if __name__ == "__main__":
    sys.exit(main())
