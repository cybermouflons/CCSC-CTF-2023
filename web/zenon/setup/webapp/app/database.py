from contextlib import contextmanager
from typing import Callable
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm.session import Session

from app.config import settings

engine = create_engine(
    settings.SQLALCHEMY_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal: Callable[..., Session] = sessionmaker(
    autocommit=False, autoflush=False, bind=engine
)

Base = declarative_base()

@contextmanager
def get_db_session():
    """Starts a database session as a context manager.
    """
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
