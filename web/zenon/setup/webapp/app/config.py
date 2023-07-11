import os
# import pathlib

# APP_NAME = "My App"
# API_V1_STR = "/api/v1"
# SQLALCHEMY_URL = os.environ["DB_URL"]
# SQLALCHEMY_USER = os.environ["DB_USER"]
# SQLALCHEMY_PASSWORD = os.environ["DB_PASSWORD"]
# APP_ROOT = pathlib.Path(__file__).parent
# TEMPLATE_DIR = APP_ROOT / "templates"
# STATIC_DIR = APP_ROOT / "static"
# SECRET_KEY = os.environ["SECRET_KEY"]
# DEBUG_ADMIN = os.environ.get("DEBUG_ADMIN", False)
# JWT_ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 60

from pydantic import BaseSettings
from typing import List
from pydantic import AnyHttpUrl


class Settings(BaseSettings):
    API_V1_STR: str = ""
    PROJECT_NAME: str = "Boilerplate"
    DESCRIPTION: str = "Boilerplate app with fastapi and jinja2"

    SQLALCHEMY_URL: str = "sqlite:///db.sqlite"
    SQLALCHEMY_USER: str = "ctf"
    SQLALCHEMY_PASSWORD: str = "ctf"

    ACCESS_TOKEN_EXPIRE_MINUTES=3600
    SECRET_KEY = os.environ.get("SECRET_KEY", "JustAnotheerSecretKey")
    ALGORITHM="HS256"

settings = Settings()