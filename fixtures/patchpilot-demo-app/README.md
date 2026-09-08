# patchpilot-demo-app

**This repository is intentionally vulnerable.** It is the deterministic demo target for
[PatchPilot](../..): a small FastAPI service whose `requirements.txt` pins dependency versions with
real, historical security advisories, chosen so that every PatchPilot decision class appears at least
once. Do not deploy it. Pull requests opened here by PatchPilot are closed by a nightly reset.

| package | pinned | why it is here |
|---|---|---|
| pyjwt | 2.10.0 | `jwt.decode(..., issuer=...)` is called in `app/auth.py` → reachable, auth tier |
| requests | 2.31.0 | `requests.Session` and `requests.get` used with caller-supplied URLs → reachable |
| urllib3 | 2.2.1 | imported, but `ProxyManager` never used → advisory not reachable |
| jinja2 | 3.1.3 | templates rendered, `xmlattr` filter never used → not reachable |
| pillow | 10.2.0 | `Image.open`/`thumbnail` only, `ImageCms` never imported → not reachable |
| python-multipart | 0.0.6 | file upload endpoint uses `UploadFile`/`Form` → reachable, patch bump |
| starlette | 0.27.0 | same upload path → reachable, but the fix needs a FastAPI bump that breaks tests |
| cryptography | 42.0.0 | `Fernet` only, `pkcs12` never used → not reachable, but crypto tier |
| black | 23.12.1 | dev-only dependency, never imported by the app |
