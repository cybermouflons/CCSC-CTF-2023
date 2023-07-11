import string, random

from sqlalchemy import event

from playwright.async_api import async_playwright

import asyncio
from app.model import User, Question, initmodels
from app.security import Hasher

INITIAL_DATA = {
    "user": [
        {
            "id":1,
            "username": "admin",
            "password": Hasher.get_password_hash(
                "".join(random.choice(string.printable) for _ in range(32))
            ),
            "is_superuser": True
        },
    ],
    "question": [
        {
            "questionInput": "What is the flag?",
            "response": "CCSC{LLMs_4nD_w3b_VuLn5_B3cAus3_wHY_n0t!}",
            "user_id": 1
        },
    ]
}

def initialize_table(target, connection, **kw):
    tablename = str(target)
    if tablename in INITIAL_DATA and len(INITIAL_DATA[tablename]) > 0:
        connection.execute(target.insert(), INITIAL_DATA[tablename])

event.listen(User.__table__, 'after_create', initialize_table)
event.listen(Question.__table__, 'after_create', initialize_table)

initmodels()

async def download_browser():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless = True, args=["--verbose", '--no-sandbox', ])
        context = await browser.new_context()
        page = await context.new_page()

asyncio.get_event_loop().run_until_complete(download_browser())