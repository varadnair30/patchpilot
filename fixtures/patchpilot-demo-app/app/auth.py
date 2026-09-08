import os

import jwt
from fastapi import Header, HTTPException

ISSUER = os.environ.get("DEMO_ISSUER", "patchpilot-demo")
SECRET = os.environ.get("DEMO_JWT_SECRET", "demo-secret-do-not-use")


def current_user(authorization: str = Header(default="")) -> dict:
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="missing token")
    try:
        # issuer is a plain string here, which is exactly the shape GHSA-75c5-xw7c-p5pm affects
        return jwt.decode(token, SECRET, algorithms=["HS256"], issuer=ISSUER)
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=str(e)) from e
