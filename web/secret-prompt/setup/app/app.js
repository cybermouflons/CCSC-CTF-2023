import express from "express";
import rateLimit from "express-rate-limit";
import bodyParser from "body-parser";

const app = express();
const port = process.env.port || 3000;

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: false }));

import PuppeteerClient from "./puppeteer/client.js";
const puppeteerClient = new PuppeteerClient();

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 10, // Maximum number of requests within the time window
  message: "Too many requests from this IP. Please try again later.",
});
app.use(limiter);

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});

app.post("/summarize", (req, res) => {
  const urlString = req.body.page;
  let parsedUrl;
  try {
    parsedUrl = new URL(urlString);
    if (
      !parsedUrl?.protocol?.toLowerCase().startsWith("http") ||
      !parsedUrl?.host
    ) {
      return res.status(400).send("Invalid URL.");
    }
  } catch (e) {
    console.error(`[/summarize] ${e}`);
    return res.status(400).send("Invalid URL.");
  }

  puppeteerClient.visit(
    parsedUrl.toString(),
    req.protocol + "://" + req.hostname + ":" + port,
    process.env.FLAG || "CCSC{not-a-flag-talk-to-an-admin}"
  );

  res.send(
    `We are in the process of summarizing the contents of ${urlString}. The results will be stored safely for you to see when we are out of beta next year.`
  );
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
