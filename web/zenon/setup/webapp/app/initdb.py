import random
import string

from app.model import User, initmodels
from app.security import Hasher
from sqlalchemy import event

INITIAL_DATA = {
    "user": [
        {
            "id": 1,
            "username": "admin",
            "password": Hasher.get_password_hash(
                "".join(random.choice(string.printable) for _ in range(32))
            ),
            "is_superuser": True,
        },
    ]
}


def initialize_table(target, connection, **kw):
    tablename = str(target)
    if tablename in INITIAL_DATA and len(INITIAL_DATA[tablename]) > 0:
        connection.execute(target.insert(), INITIAL_DATA[tablename])


event.listen(User.__table__, "after_create", initialize_table)

initmodels()
