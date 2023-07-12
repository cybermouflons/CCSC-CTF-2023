from typing import Optional

from app.config import settings
from app.crud import get_user_by_username
from app.database import get_db_session as _get_db_session
from fastapi import Cookie, Depends, HTTPException, status
from jose import jwt
from pydantic import ValidationError


def require_token(access_token: Optional[str] = Cookie(None)):
    try:
        if not access_token:
            raise Exception
        token = access_token.split(" ")[-1]
    except Exception as e:
        raise HTTPException(
            status_code=302, detail="Not authorized", headers={"Location": "/login"}
        )
    return token


def require_login(token: str = Depends(require_token)):
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
    except (jwt.JWTError, ValidationError):
        raise HTTPException(
            status_code=302, detail="Not authorized", headers={"Location": "/login"}
        )
    username = payload["sub"]
    with _get_db_session() as db:
        user = get_user_by_username(username, db)
        if not user:
            raise HTTPException(
                status_code=302, detail="Not authorized", headers={"Location": "/login"}
            )
    return user
