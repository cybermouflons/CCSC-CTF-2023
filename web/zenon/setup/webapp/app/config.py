import random, string
from pydantic import BaseSettings

class Settings(BaseSettings):
    API_V1_STR: str = ""
    PROJECT_NAME: str = "Boilerplate"
    DESCRIPTION: str = "Boilerplate app with fastapi and jinja2"

    SQLALCHEMY_URL: str = "sqlite:///db.sqlite"
    SQLALCHEMY_USER: str = "ctf"
    SQLALCHEMY_PASSWORD: str = "ctf"
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://ctf:ctf@db/ctf'

    BOT_HOSTNAME: str = "localhost"

    ACCESS_TOKEN_EXPIRE_MINUTES=3600
    SECRET_KEY: str
    ALGORITHM="HS256"

settings = Settings()