import os

from app.auth import create_access_token

from playwright.async_api import async_playwright


async def visit_url_as_admin(question_id: int):
    hostname = os.environ.get("APP_HOSTNAME", "localhost")
    access_token = create_access_token(data={"sub": "admin"})
    async with async_playwright() as p:
        question_id = int(question_id)
        browser = await p.chromium.launch(headless = True, args=["--verbose", '--no-sandbox', ])
        context = await browser.new_context()
        url = f"http://{hostname}/"
        cookies = {
            "url": url,
            "name": "access_token",
            "value": access_token
        }
        await context.add_cookies([cookies])
        page = await context.new_page()
        url = f"http://{hostname}:8000/question?id={question_id}"
        print("Visiting ", url)
        await page.goto(url)