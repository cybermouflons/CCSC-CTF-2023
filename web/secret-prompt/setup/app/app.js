import express from "express";
import rateLimit from "express-rate-limit";
import bodyParser from "body-parser";

const app = express();
const port = process.env.port || 3000;

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: false }));

import PuppeteerClient from "./puppeteer/client.js";
const puppeteerClient = new PuppeteerClient();

const escapeHTML = (str) =>
  str.replace(
    /[&<>'"]/g,
    (tag) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "'": "&#39;",
        '"': "&quot;",
      }[tag])
  );

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 5,
  message: "Too many requests from this IP. Please try again later.",
});
app.use(limiter);

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});

app.post("/summarize", (req, res) => {
  const targetURL = req.body.page;
  let parsedTargetURL;
  try {
    parsedTargetURL = new URL(targetURL);
    if (
      !parsedTargetURL?.protocol?.toLowerCase().startsWith("http") ||
      !parsedTargetURL?.host
    ) {
      return res.status(400).send("Invalid URL: " + escapeHTML(targetURL));
    }
  } catch (e) {
    return res.status(400).send("Invalid URL: " + escapeHTML(targetURL));
  }

  const originURL = req.protocol + "://" + req.headers.host;
  let parsedOriginURL;
  try {
    parsedOriginURL = new URL(originURL);
    if (
      !parsedOriginURL?.protocol?.toLowerCase().startsWith("http") ||
      !parsedOriginURL?.host ||
      (!parsedOriginURL?.hostname.endsWith("cybermouflons.com") &&
        !parsedOriginURL?.hostname.endsWith("localhost"))
    ) {
      return res
        .status(400)
        .send("Invalid Origin URL: " + escapeHTML(originURL));
    }
  } catch (e) {
    return res.status(400).send("Invalid Origin URL: " + escapeHTML(originURL));
  }

  puppeteerClient.visit(
    parsedTargetURL.toString(),
    parsedOriginURL.toString(),
    process.env.FLAG || "CCSC{not-a-flag-talk-to-an-admin}"
  );

  res.send(
    `We are in the process of summarizing the contents of ${escapeHTML(
      targetURL
    )}. Thank you for feeding me more data puny human. Now get lost. 😈`
  );
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
