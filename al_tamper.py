"""attest-lock selfcheck, tamper half: prove verification is bound to the bytes and the signature.

Two negative controls on the real urllib3 2.8.0 fixture, both offline:
  * the sha256 uv.lock pins is zeroed  -> the attestation must stop verifying (subject digest mismatch)
  * one byte of the DSSE signature is flipped -> that file fails while the untouched wheel still verifies
"""
from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path

from al_lock import FixtureFetcher, parse_uv_lock
from al_report import EXIT_VERIFY_FAIL, check_package, exit_code


def tamper_checks(ok, here: Path, fixtures: Path, lock: Path) -> None:
    fetcher = FixtureFetcher(fixtures)
    urllib3 = next(pk for pk in parse_uv_lock(lock) if pk.name == "urllib3")

    # A. Tampered lock hash: same provenance document, wrong sha256 in the lock.
    bad = copy.deepcopy(urllib3)
    bad.files[0].sha256 = "0" * 64
    r = check_package(bad, fetcher, True, {}, None)
    ok(r.verdict == "VERIFY-FAILED" and "digest" in r.files[0].detail, f"tampered digest: {r.verdict} {r.files[0].detail}")
    ok(exit_code([r], False) == EXIT_VERIFY_FAIL, "tampered digest exit code")

    # B. Tampered signature bytes: same file, same hash, corrupted DSSE signature in a copy of the fixtures.
    idx = json.loads((fixtures / "index.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(dir=here) as td:
        tdir = Path(td)
        for ent in idx.values():
            if isinstance(ent, dict) and "file" in ent:
                (tdir / ent["file"]).write_bytes((fixtures / ent["file"]).read_bytes())
        (tdir / "index.json").write_text(json.dumps(idx), encoding="utf-8")
        target = tdir / "urllib3-2.8.0.tar.gz.provenance.json"
        prov = json.loads(target.read_text(encoding="utf-8"))
        att = prov["attestation_bundles"][0]["attestations"][0]
        sig = att["envelope"]["signature"]
        att["envelope"]["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
        target.write_text(json.dumps(prov), encoding="utf-8")
        r2 = check_package(urllib3, FixtureFetcher(tdir), True, {}, None)
        ok(r2.files[0].status == "verify-failed" and r2.files[1].status == "attested",
           f"tampered sig: {[(f.status, f.detail) for f in r2.files]}")
        ok(r2.verdict == "VERIFY-FAILED", f"tampered sig verdict {r2.verdict}")
