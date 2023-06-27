import puppeteer from "puppeteer";

class Puppeteer {
  async visit(url, originURL, flag) {
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
      // set gift in localStorage
      let page = await browser.newPage();
      await page.setRequestInterception(true);
      page.on("request", (r) => {
        r.respond({
          status: 200,
          contentType: "text/plain",
          body: "nothing",
        });
      });
      console.log(`[PUPPETEER] Visiting: ${originURL}...`);
      await page.goto(originURL);
      await page.evaluate((flag) => localStorage.setItem("gift", flag), flag);
      await new Promise((r) => setTimeout(r, 350));

      const gift = await page.evaluate(() => {
        return localStorage.getItem("gift");
      });
      if (gift !== flag) {
        throw new Error("gift wasn't set properly");
      }

      await page.close();
      // done setting gift in localStorage

      page = await browser.newPage();
      page.setDefaultTimeout(15 * 1000);

      page.on("dialog", async (dialog) => {
        await dialog.dismiss();
      });

      console.log(`[PUPPETEER] Visiting: ${url}...`);

      const res = await page.goto(url, { waitUntil: "networkidle2" });

      await new Promise((r) => setTimeout(r, 5000));

      console.log(`[PUPPETEER] Status: ${res.status()} URL: ${url}`);
    } catch (err) {
      console.error(`[PUPPETEER] ${err.message}`);
    } finally {
      await browser.close();
    }
  }
}

export default Puppeteer;
