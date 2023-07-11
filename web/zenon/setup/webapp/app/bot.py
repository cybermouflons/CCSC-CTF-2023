from app.auth import create_access_token


from playwright.async_api import async_playwright


async def visit_url_as_admin(url: str):
    access_token = create_access_token(data={"sub": "admin"})
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless = True, args=["--verbose", '--no-sandbox', ])
        context = await browser.new_context()
        cookies = {
            "url": url,
            "name": "access_token",
            "value": access_token
        }
        await context.add_cookies([cookies])
        page = await context.new_page()
        print("Visiting ", url)
        await page.goto(url)