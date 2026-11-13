# pypi-provenance-audit

Checks every file pinned in a `uv.lock` against the signed publishing record (Sigstore attestation) that PyPI holds for it, and flags packages whose signing repository differs from the repository they declare.

Read-only: it parses your lockfile and queries PyPI's public integrity endpoint. It installs nothing and runs nothing from your project.

## Quickstart

Needs [uv](https://docs.astral.sh/uv/) (dependencies are declared in the script header, so there is nothing to install first).

```bash
git clone https://github.com/MegaStretch23/pypi-provenance-audit
cd pypi-provenance-audit
uv run main.py --lock /path/to/your/uv.lock
```

Try it with no network and no lockfile of your own (saved real PyPI responses):

```bash
uv run main.py --lock fixtures/project/uv.lock.toml --fixtures fixtures --offline
uv run main.py --selfcheck          # 28 assertions, offline
```

## What it does

For each `registry = "https://pypi.org/simple"` package in the lock it fetches `pypi.org/integrity/<name>/<version>/<file>/provenance` for every pinned sdist and wheel and verifies each Sigstore bundle with `pypi-attestations` (sigstore-python underneath) against the Trusted Publisher PyPI recorded **and** the sha256 your lock pins. It reads the source repository from the signing certificate and compares it with the repository URLs in the project's PyPI metadata.

One row per package: attested files n/m, attested repo, declared repo, verdict.

| verdict | meaning |
|---|---|
| MATCH | files verified; signing repo equals the declared (or `--expect`ed) repo |
| MISMATCH | signing repo differs from the declared or expected repo |
| NO-REPO-DECLARED | attested, but the package declares no repo to compare with |
| UNATTESTED | PyPI holds no attestation for the package's files |
| VERIFY-FAILED | an attestation exists but does not verify (hash or signature) |
| SKIPPED | not from pypi.org |

Exit codes: `0` ok, `2` any MISMATCH, `3` any attestation that fails to verify, `4` any UNATTESTED with `--require-attested`, `1` usage or lock error.

Flags: `--expect PKG=github.com/owner/repo` (your own expectation beats the self-declared metadata), `--offline` (embedded trust root, no TUF refresh), `--max-files N`, `--workers N`, `--json`, `--out report.json`, `--fixtures DIR`, `--require-attested`.

## Sample output

Offline run on the bundled fixture (a real `uv lock` of urllib3 2.8.0 and six 1.16.0; real PyPI responses saved in `fixtures/`), saved in `examples/sample_offline_output.txt`:

```
Installed 32 packages in 75ms
package  version  attested  attested repo               declared repo               verdict
-------  -------  --------  --------------------------  --------------------------  ----------
six      1.16.0   0/2       -                           github.com/benjaminp/six    UNATTESTED
urllib3  2.8.0    2/2       github.com/urllib3/urllib3  github.com/urllib3/urllib3  MATCH

2 packages, 2/4 files attested+verified; MATCH 1, UNATTESTED 1
exit 0
```

A larger saved run (live PyPI, 2026-09-26, 36 packages, 77 files, about 25 s): 45 files attested and verified, 21 MATCH, 15 UNATTESTED, 0 verification failures, exit 0. Full table: `examples/sample_live_table.txt`, JSON report: `fixtures/live/report.json`. Attestation coverage on PyPI changes over time, so a fresh run on the same lock can differ.

## Limits

- A MATCH is a consistency check, not proof of intent: the declared-repo metadata is uploaded by the same publisher as the attestation. `--expect` is the stronger control.
- Only PyPI is queried; other indexes are SKIPPED. GitLab, Google and CircleCI publishers are mapped but only GitHub publishers were seen live.
- No caching between runs and no "which files would uv actually install" filter; `--max-files` is the blunt substitute.
- uv.lock only (no pip, poetry or SBOM input).

## Want it done for you?

A written version of this audit (one row per package, a read of the unsigned and mismatched packages and what to do about each, one re-check after changes) is offered as a paid service at $300 per lockfile. It is being listed on the Gumroad store: <https://vedovino.gumroad.com/>.

## License

MIT
