import xml.etree.ElementTree as ET
from typing import Optional

import requests

PYPI_RSS = "https://pypi.org/rss/updates.xml"
PYPI_JSON = "https://pypi.org/pypi/{name}/json"

_session = requests.Session()
_session.headers["User-Agent"] = "mlpro-scanner/1.0 (security research)"


def get_recent_packages(limit: int = 100) -> list[dict]:
    resp = _session.get(PYPI_RSS, timeout=30)
    resp.raise_for_status()
    root = ET.fromstring(resp.content)
    packages = []
    for item in root.findall(".//item")[:limit]:
        title = item.findtext("title", "").strip()
        parts = title.rsplit(" ", 1)
        if len(parts) == 2:
            packages.append({"name": parts[0], "version": parts[1]})
    return packages


def get_package_metadata(name: str) -> Optional[dict]:
    resp = _session.get(PYPI_JSON.format(name=name), timeout=30)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    data = resp.json()
    info = data["info"]
    version = info["version"]

    releases = data.get("releases", {}).get(version, [])
    tarball_url = next(
        (r["url"] for r in releases if r.get("packagetype") == "sdist"),
        next((r.get("url") for r in releases), None),
    )

    return {
        "registry": "pypi",
        "name": info["name"],
        "version": version,
        "author": info.get("author") or info.get("maintainer"),
        "description": info.get("summary"),
        "homepage": info.get("home_page"),
        "repository": (info.get("project_urls") or {}).get("Source"),
        "keywords": [k.strip() for k in (info.get("keywords") or "").split(",") if k.strip()],
        "tarball_url": tarball_url,
        "downloads_last_month": 0,
        "version_count": len(data.get("releases", {})),
    }
