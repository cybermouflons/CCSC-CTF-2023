from app.model import Question, User
from app.schema import UserCreate
from app.security import Hasher
from sqlalchemy.orm import Session


def create_new_user(user: UserCreate, db: Session):
    user = User(
        username=user.username,
        password=Hasher.get_password_hash(user.password),
        is_superuser=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_user_by_username(username: str, db: Session):
    return db.query(User).filter(User.username == username).first()


def create_new_question(questionInput: str, response: str, user_id: int, db: Session):
    question = Question(questionInput=questionInput, response=response, user_id=user_id)
    db.add(question)
    db.commit()
    db.refresh(question)
    return question


def get_question_by_id(id: id, db: Session):
    return db.query(Question).filter(Question.id == id).first()
