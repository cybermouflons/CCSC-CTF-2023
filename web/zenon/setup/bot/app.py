from datetime import datetime, timedelta
from typing import Optional

from config import settings
from fastapi import FastAPI
from jose import jwt
from playwright.async_api import async_playwright

app = FastAPI()


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

@app.get("/visit_question")
async def visit(id: int):
    access_token = create_access_token(data={"sub": "admin"})
    try:
        async with async_playwright() as p:
            id = int(id)
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--verbose",
                    "--no-sandbox",
                ],
            )
            context = await browser.new_context()
            url = f"http://{settings.APP_HOSTNAME}/"
            flag_cookie = {
                "url": url,
                "name": "flag",
                "value": "CCSC{LLMs_4nD_w3b_VuLn5_B3cAus3_wHY_n0t!}",
                "httpOnly": True,
            }
            token_cookie = {
                "url": url,
                "name": "access_token",
                "value": access_token,
                "httpOnly": True,
            }
            await context.add_cookies([flag_cookie, token_cookie])
            page = await context.new_page()
            url = f"http://{settings.APP_HOSTNAME}:8000/question?id={id}"
            print("Visiting ", url)
            async with page.expect_console_message(timeout=5000) as msg_info:
                await page.goto(url)
                await page.content()  # triggers javascript
            print(await msg_info.value)
    except Exception as e:
        print("Exception", e)

    return {"status": "OK"}
