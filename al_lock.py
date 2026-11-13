"""attest-lock: uv.lock parsing and the two PyPI fetchers (network / saved fixtures)."""
from __future__ import annotations

import json
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

USER_AGENT = "attest-lock/0.1 (+uv.lock attestation checker)"


@dataclass
class LockedFile:
    filename: str
    sha256: str
    url: str


@dataclass
class LockedPackage:
    name: str
    version: str
    source: str  # "pypi" | anything else (skipped)
    files: list[LockedFile] = field(default_factory=list)


def parse_uv_lock(path: Path) -> list[LockedPackage]:
    """Every registry package in a uv.lock with its pinned sdist + wheels (sha256 + URL).

    Virtual / editable / git / path sources have nothing on PyPI and are dropped."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    out: list[LockedPackage] = []
    for pkg in data.get("package", []):
        src = pkg.get("source", {})
        registry = src.get("registry", "")
        if not registry:
            continue
        source = "pypi" if registry.rstrip("/").startswith("https://pypi.org/simple") else registry
        files: list[LockedFile] = []
        entries = ([pkg["sdist"]] if "sdist" in pkg else []) + list(pkg.get("wheels", []))
        for e in entries:
            h = e.get("hash", "")
            url = e.get("url", "")
            if not h.startswith("sha256:") or not url:
                continue
            files.append(LockedFile(filename=url.rsplit("/", 1)[-1], sha256=h[len("sha256:"):], url=url))
        out.append(LockedPackage(name=pkg["name"], version=str(pkg["version"]), source=source, files=files))
    return out


class HttpFetcher:
    """Plain urllib GET. Returns (status, body). Never raises on HTTP errors."""

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    def get(self, url: str, accept: str | None = None) -> tuple[int, bytes]:
        headers = {"User-Agent": USER_AGENT}
        if accept:
            headers["Accept"] = accept
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            return 0, str(e).encode()


class FixtureFetcher:
    """Offline fetcher: URL -> saved response, driven by <dir>/index.json.

    index.json maps a URL to {"status": N, "file": "saved.json"} or {"status": N, "body": "..."}."""

    def __init__(self, directory: Path):
        self.dir = directory
        self.index: dict = json.loads((directory / "index.json").read_text(encoding="utf-8"))

    def get(self, url: str, accept: str | None = None) -> tuple[int, bytes]:
        ent = self.index.get(url)
        if ent is None:
            return 404, b'{"message":"not in fixture index"}'
        if "file" in ent:
            return int(ent.get("status", 200)), (self.dir / ent["file"]).read_bytes()
        return int(ent.get("status", 404)), ent.get("body", "").encode()
