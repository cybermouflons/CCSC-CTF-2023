// required packages
const puppeteer = require("puppeteer");

// sleep
const delay = (time) => {
    return new Promise(resolve => setTimeout(resolve, time));
}

// navigate
async function goto(url) { 
	const browser = await puppeteer.launch({
        headless: true,
		ignoreHTTPSErrors: true,
		args: [ "--no-sandbox", "--ignore-certificate-errors" ],
        timeout: 3000
	});

	admin_username = process.env.admin_username
	admin_password = process.env.admin_password
	host = process.env.host
	
	const page = await browser.newPage();

	await page.setDefaultNavigationTimeout(5000);

	await page.goto("https://" + host + "/login");
	const username = await page.waitForSelector("#username");
	const password = await page.waitForSelector("#password");
	await username.type(admin_username);
	await password.type(admin_password);
	await page.keyboard.press("Enter");
	
	cookie = await page.cookies();
	// console.log(cookie);

	cookie[0].domain = process.env.cssc_host
	
	await page.setCookie(cookie[0])

    await page.waitForNavigation();

    // Go to provided URL
	try {
        console.log("Visiting: " + url);
		// cookie = await page.cookies();
		// console.log(cookie);
		
	    await page.goto(url);

		
		
	} catch {}

    await delay(1000);

    browser.close();
	return;
}

module.exports = { goto };
