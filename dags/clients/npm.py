from typing import Optional

import requests

NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"
NPM_META = "https://registry.npmjs.org/{name}"

_session = requests.Session()
_session.headers["User-Agent"] = "mlpro-scanner/1.0 (security research)"


def get_recent_packages(limit: int = 100) -> list[dict]:
    resp = _session.get(
        NPM_SEARCH,
        params={"text": "a", "from": 0, "size": min(limit, 250)},
        timeout=30,
    )
    resp.raise_for_status()
    objects = resp.json().get("objects", [])
    return [
        {"name": obj["package"]["name"], "version": obj["package"]["version"]}
        for obj in objects
    ]


def get_package_metadata(name: str) -> Optional[dict]:
    resp = _session.get(NPM_META.format(name=name), timeout=30)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    data = resp.json()

    version = (data.get("dist-tags") or {}).get("latest")
    if not version:
        return None

    version_data = data.get("versions", {}).get(version, {})
    tarball_url = version_data.get("dist", {}).get("tarball")
    author_info = data.get("author") or {}
    repo_info = data.get("repository") or {}

    return {
        "registry": "npm",
        "name": data.get("name"),
        "version": version,
        "author": author_info.get("name") if isinstance(author_info, dict) else str(author_info),
        "description": data.get("description"),
        "homepage": data.get("homepage"),
        "repository": repo_info.get("url") if isinstance(repo_info, dict) else None,
        "keywords": data.get("keywords") or [],
        "tarball_url": tarball_url,
        "downloads_last_month": 0,
        "version_count": len(data.get("versions", {})),
    }
