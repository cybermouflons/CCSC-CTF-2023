import puppeteer from "puppeteer";

class Puppeteer {
  async visit(url, cookieValue = "") {
    const browser = await puppeteer.launch({
      headless: true,
      executablePath: process.env.CHROME_BIN || "/usr/bin/chromium-browser",
      args: [
        "--headless",
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
      ],
    });
    try {
      const page = await browser.newPage();
      page.setDefaultTimeout(15 * 1000);

      page.on("dialog", async (dialog) => {
        console.log(dialog.message());
        await dialog.dismiss();
      });

      console.log(`[PUPPETEER] Using cookie: ${cookieValue.substr(0, 8)}...`);

      await page.setCookie({
        value: cookieValue,
        domain: "secret.prompt",
        expires: Date.now() / 1000 + 100,
        name: "flag",
        secure: false,
        httpOnly: false,
      });

      console.log(`[PUPPETEER] Visiting: ${url}...`);

      const res = await page.goto(url);

      console.log(`[PUPPETEER] Status: ${res.status()} URL: ${url}`);
    } catch (err) {
      console.error(`[PUPPETEER] ${err.message}`);
    } finally {
      await browser.close();
    }
  }
}

export default Puppeteer;
