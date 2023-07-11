from pydantic import BaseModel
from pydantic import Field


class UserLogin(BaseModel):
    username: str
    password: str = Field(..., min_length=1)


class UserCreate(UserLogin):
    ...


class QuestionInput(BaseModel):
    questionInput: str


class ContactSupport(BaseModel):
    question_id: str
