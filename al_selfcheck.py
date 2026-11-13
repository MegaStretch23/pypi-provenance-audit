"""attest-lock --selfcheck: the real mechanism end to end, offline, on saved PyPI responses.

fixtures/project/uv.lock.toml is a real `uv lock` of urllib3 2.8.0 + six 1.16.0 (kept with a .toml
suffix so review tooling that filters on extension shows it; the parser does not care).
fixtures/index.json maps each PyPI URL the run needs to the saved response and pins the sha256
of both fixture lockfiles. The tamper tests live in al_tamper.py."""
from __future__ import annotations

import hashlib
import json
import logging
import subprocess
import sys
from pathlib import Path

from al_lock import parse_uv_lock
from al_report import EXIT_MISMATCH, EXIT_UNATTESTED
from al_tamper import tamper_checks
from al_verify import publisher_repo, repos_from_text

HERE = Path(__file__).resolve().parent


def selfcheck() -> int:
    logging.getLogger("sigstore").setLevel(logging.ERROR)
    fixtures = HERE / "fixtures"
    lock = fixtures / "project" / "uv.lock.toml"
    # The subprocess runs with cwd=HERE and RELATIVE paths so the report it writes
    # (selfcheck_report.json, kept in the tree) never embeds this machine's absolute path.
    rel_lock = lock.relative_to(HERE).as_posix()
    rel_fixtures = fixtures.relative_to(HERE).as_posix()
    checks = 0

    def ok(cond: bool, msg: str) -> None:
        nonlocal checks
        checks += 1
        if not cond:
            raise SystemExit(f"SELFCHECK FAIL [{checks}]: {msg}")

    # 0. The fixture lockfiles exist and are the bytes the fixture index pins.
    idx = json.loads((fixtures / "index.json").read_text(encoding="utf-8"))
    for rel, want in idx["lockfiles"].items():
        p = fixtures / rel
        ok(p.is_file(), f"fixture lockfile missing: fixtures/{rel}")
        got = hashlib.sha256(p.read_bytes()).hexdigest()
        ok(got == want, f"fixtures/{rel} sha256 {got} != pinned {want}")
    ok(len(parse_uv_lock(fixtures / "live" / "uv.lock.toml")) == 36, "live lock should parse to 36 registry packages")

    # 1. Run the CLI as a subprocess and assert against the report file it writes.
    report = HERE / "selfcheck_report.json"
    if report.exists():
        report.unlink()
    cmd = [sys.executable, "main.py", "--lock", rel_lock, "--fixtures", rel_fixtures, "--offline", "--out", report.name]
    sub = dict(cwd=HERE, capture_output=True, text=True, encoding="utf-8", errors="replace")
    p = subprocess.run(cmd, **sub)
    ok(p.returncode == 0, f"CLI exit {p.returncode}\n{p.stdout}\n{p.stderr}")
    ok(report.exists(), "CLI did not write --out report")
    data = json.loads(report.read_text(encoding="utf-8"))
    by = {r["name"]: r for r in data["packages"]}
    ok(set(by) == {"six", "urllib3"}, f"packages parsed from lock: {sorted(by)}")
    u = by["urllib3"]
    ok(u["attested"] == 2 and u["total"] == 2, f"urllib3 attested {u['attested']}/{u['total']}")
    ok(all(f["status"] == "attested" and f["attestation_type"].endswith("/publish/v1") for f in u["files"]),
       f"urllib3 files: {u['files']}")
    ok(u["repos"] == ["github.com/urllib3/urllib3"], f"urllib3 repos {u['repos']}")
    ok(u["files"][0]["workflow"] == "publish.yml", f"workflow {u['files'][0]['workflow']}")
    ok("github.com/urllib3/urllib3" in u["declared"], f"urllib3 declared {u['declared']}")
    ok(u["verdict"] == "MATCH", f"urllib3 verdict {u['verdict']}")
    s = by["six"]
    ok(s["attested"] == 0 and s["total"] == 2 and s["verdict"] == "UNATTESTED", f"six {s}")
    ok(s["declared"] == ["github.com/benjaminp/six"], f"six declared {s['declared']}")
    ok(data["exit_code"] == 0 and data["lock"] == rel_lock, f"report envelope {data['exit_code']} {data['lock']}")
    raw = report.read_text(encoding="utf-8")
    ok(str(HERE) not in raw and HERE.as_posix() not in raw and not Path(data["lock"]).is_absolute(),
       "report embeds an absolute machine path")
    # the table the CLI printed must agree with the report it wrote
    ok("urllib3  2.8.0    2/2       github.com/urllib3/urllib3" in p.stdout and "MATCH" in p.stdout, f"table:\n{p.stdout}")
    ok("six      1.16.0   0/2       -" in p.stdout and "UNATTESTED" in p.stdout, f"table:\n{p.stdout}")

    # 2. --expect naming a different repo must flip the verdict and exit 2.
    p2 = subprocess.run(cmd[:-2] + ["--expect", "urllib3=github.com/evil/urllib3"], **sub)
    ok(p2.returncode == EXIT_MISMATCH and "MISMATCH" in p2.stdout, f"expect-mismatch exit {p2.returncode}\n{p2.stdout}")

    # 3. --require-attested turns the unattested six into exit 4.
    p3 = subprocess.run(cmd[:-2] + ["--require-attested"], **sub)
    ok(p3.returncode == EXIT_UNATTESTED, f"require-attested exit {p3.returncode}")

    # 4-5. Tampered lock hash and tampered signature bytes (al_tamper.py).
    tamper_checks(ok, HERE, fixtures, lock)

    # 6. Unit behaviour of the repo matcher.
    ok(repos_from_text("https://github.com/Foo/Bar.git/issues", "https://gitlab.com/a/b") == {"github.com/foo/bar", "gitlab.com/a/b"},
       "repo regex")
    ok(publisher_repo(type("P", (), {"kind": "GitHub", "repository": "urllib3/urllib3"})()) == "github.com/urllib3/urllib3", "publisher_repo")

    print(f"selfcheck OK: {checks} assertions against {report.name} and the live table output")
    return 0
