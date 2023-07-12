from typing import Any

from app.database import engine
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import as_declarative, declared_attr, relationship


@as_declarative()
class Base:
    id: Any
    __name__: str

    # to generate tablename from classname
    @declared_attr
    def __tablename__(cls) -> str:
        return cls.__name__.lower()


class User(Base):
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, nullable=False, unique=True, index=True)
    password = Column(String, nullable=False)
    is_superuser = Column(Boolean(), default=False)

    # One-to-many relationship: User to Question
    questions = relationship("Question", lazy="subquery", back_populates="user")


class Question(Base):
    id = Column(Integer, primary_key=True, index=True)
    questionInput = Column(String, nullable=False)
    response = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey("user.id"))

    user = relationship("User", back_populates="questions")


def initmodels():
    Base.metadata.create_all(engine)
