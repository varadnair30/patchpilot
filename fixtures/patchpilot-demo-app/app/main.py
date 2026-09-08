"""Tiny document-intake service: upload a file, get a signed receipt, notify by email."""

from fastapi import Depends, FastAPI, File, Form, UploadFile

from app.auth import current_user
from app.http_client import fetch_metadata
from app.images import make_thumbnail
from app.notify import render_receipt_email
from app.secrets import seal

app = FastAPI(title="patchpilot-demo-app")


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.post("/upload")
async def upload(
    file: UploadFile = File(...),
    title: str = Form(...),
    source_url: str | None = Form(None),
    user: dict = Depends(current_user),
) -> dict:
    data = await file.read()
    thumb_len = len(make_thumbnail(data)) if file.content_type in ("image/jpeg", "image/png") else 0
    meta = fetch_metadata(source_url) if source_url else {}
    receipt = seal(f"{user['sub']}:{title}:{len(data)}")
    email_html = render_receipt_email(user=user, title=title, receipt=receipt)
    return {"title": title, "bytes": len(data), "thumbnail_bytes": thumb_len, "meta": meta,
            "receipt": receipt, "email_preview_len": len(email_html)}
