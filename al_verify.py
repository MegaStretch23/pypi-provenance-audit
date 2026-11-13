"""attest-lock: per-file Sigstore verification against PyPI's provenance document.

Each pinned file is looked up on pypi.org/integrity/<name>/<version>/<file>/provenance.
Every bundle in the document is verified with pypi-attestations (sigstore-python underneath)
against (a) the Trusted Publisher identity PyPI recorded and (b) the sha256 uv.lock pins.
The signing certificate's source-repo claim is what the package-level comparison uses."""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass

from al_lock import LockedFile

INTEGRITY_ACCEPT = "application/vnd.pypi.integrity.v1+json"
OID_SOURCE_REPO_URI = "1.3.6.1.4.1.57264.1.12"
REPO_HOSTS = ("github.com", "gitlab.com", "codeberg.org", "bitbucket.org")
_REPO_RE = re.compile(
    r"https?://(?:www\.)?(" + "|".join(re.escape(h) for h in REPO_HOSTS) + r")/([^/\s#?]+)/([^/\s#?]+)",
    re.I,
)

# Each verify() refreshes the Sigstore TUF trust root; concurrent refreshes race on the
# on-disk TUF cache and surface as spurious "TUFError: Failed to refresh TUF metadata"
# (observed live 2026-09-26: 14 of 36 packages). Network fetches stay parallel; only the
# sub-second verify step is serialized.
_VERIFY_LOCK = threading.Lock()


def normalize_repo(host: str, owner: str, repo: str) -> str:
    repo = repo[:-4] if repo.lower().endswith(".git") else repo
    return f"{host.lower()}/{owner.lower()}/{repo.lower()}"


def repos_from_text(*texts: str | None) -> set[str]:
    """Every host/owner/repo (normalized) found in the given strings."""
    found: set[str] = set()
    for t in texts:
        if not t:
            continue
        for m in _REPO_RE.finditer(t):
            found.add(normalize_repo(*m.groups()))
    return found


def declared_repos(meta: dict | None) -> set[str]:
    """Repos the project declares in its PyPI JSON metadata (home_page + project_urls)."""
    if not meta:
        return set()
    info = meta.get("info", {})
    urls = list((info.get("project_urls") or {}).values())
    return repos_from_text(info.get("home_page"), *urls)


def publisher_repo(publisher) -> str:
    """The repo PyPI recorded as the Trusted Publisher, normalized like declared repos."""
    kind = getattr(publisher, "kind", "?")
    repo = getattr(publisher, "repository", None)
    if kind == "GitHub" and repo:
        return normalize_repo("github.com", *repo.split("/", 1))
    if kind == "GitLab" and repo:
        owner, _, name = repo.partition("/")
        return normalize_repo("gitlab.com", owner, name)
    return f"{kind}:{repo or getattr(publisher, 'email', '?')}"


@dataclass
class FileResult:
    filename: str
    status: str  # attested | unattested | verify-failed | error
    detail: str = ""
    repo: str = ""  # repo from the signing certificate (source repo URI claim)
    publisher: str = ""  # repo PyPI recorded as the Trusted Publisher
    workflow: str = ""
    attestation_type: str = ""


def verify_file(name: str, version: str, f: LockedFile, fetcher, offline: bool) -> FileResult:
    from pypi_attestations import Distribution, Provenance

    url = f"https://pypi.org/integrity/{name}/{version}/{f.filename}/provenance"
    status, body = fetcher.get(url, accept=INTEGRITY_ACCEPT)
    if status == 404:
        return FileResult(f.filename, "unattested", "no provenance on PyPI")
    if status != 200:
        return FileResult(f.filename, "error", f"HTTP {status} from integrity endpoint")
    try:
        prov = Provenance.model_validate_json(body)
    except Exception as e:  # noqa: BLE001
        return FileResult(f.filename, "error", f"provenance parse: {type(e).__name__}: {e}"[:200])
    dist = Distribution(name=f.filename, digest=f.sha256)
    last: FileResult | None = None
    for bundle in prov.attestation_bundles:
        pub = publisher_repo(bundle.publisher)
        wf = getattr(bundle.publisher, "workflow", "") or ""
        for att in bundle.attestations:
            try:
                with _VERIFY_LOCK:
                    pred_type, _ = att.verify(bundle.publisher, dist, offline=offline)
            except Exception as e:  # noqa: BLE001
                last = FileResult(f.filename, "verify-failed", f"{type(e).__name__}: {e}"[:200],
                                  publisher=pub, workflow=wf)
                continue
            claims = att.certificate_claims or {}
            src = claims.get(OID_SOURCE_REPO_URI, "")
            m = _REPO_RE.search(src)
            repo = normalize_repo(*m.groups()) if m else (src or pub)
            return FileResult(f.filename, "attested", "verified", repo=repo, publisher=pub,
                              workflow=wf, attestation_type=pred_type)
    return last or FileResult(f.filename, "error", "provenance had no attestations")
