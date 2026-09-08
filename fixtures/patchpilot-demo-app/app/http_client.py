import requests
import urllib3  # imported for the Retry helper; ProxyManager is never used

_retry = urllib3.util.Retry(total=2, backoff_factor=0.2)
_session = requests.Session()
_session.mount("https://", requests.adapters.HTTPAdapter(max_retries=_retry))


def fetch_metadata(url: str) -> dict:
    """Fetch a caller-supplied URL and return a few response headers."""
    resp = _session.get(url, timeout=5)
    quick = requests.get(url, timeout=5, allow_redirects=False)
    return {"status": resp.status_code, "content_type": resp.headers.get("content-type"),
            "redirect": quick.headers.get("location")}
