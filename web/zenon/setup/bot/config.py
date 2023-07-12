from pydantic import BaseSettings


class Settings(BaseSettings):
    APP_HOSTNAME: str = "localhost"
    ACCESS_TOKEN_EXPIRE_MINUTES=3600
    SECRET_KEY: str 
    ALGORITHM="HS256"

settings = Settings()