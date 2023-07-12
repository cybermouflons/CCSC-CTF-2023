from datetime import datetime, timedelta
from typing import Optional

from app.config import settings
from app.crud import get_user_by_username
from app.database import SessionLocal
from app.security import Hasher
from jose import jwt


def authenticate_user(username: str, password: str, db: SessionLocal):
    user = get_user_by_username(username, db)
    if not user:
        return False
    if not Hasher.verify_password(password, user.password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt
