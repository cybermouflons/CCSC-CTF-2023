const express = require('express');
const nunjucks = require('nunjucks');
const Database = require('./database');
const bodyParser = require('body-parser');
const flash = require('express-flash');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const http = require('http');
const https = require('https');
const {join} = require('path');



// const http_port = 3000;
// const https_port = 3443;
const host = process.env.host

var privateKey  = fs.readFileSync(join(__dirname, 'sslcert', 'server.key'), 'utf8');
var certificate = fs.readFileSync(join(__dirname, 'sslcert', 'server.crt'), 'utf8');
var credentials = {key: privateKey, cert: certificate};



app = express();
var expressWs = require('express-ws');

// var httpServer = http.createServer(app);
var httpsServer = https.createServer(credentials, app);

// expressWs(app);

expressWs(app, httpsServer);

const routes = require('./routes'); // Load routers after expressws, to allow it to override prototype


const db = new Database('cswsh.db');

nunjucks.configure(['views', 'uploads'], {
  autoescape: true,
  express: app
}).addFilter('tojson', function(obj) {
  return JSON.stringify(obj);
});


app.use(session({
  name: `session`,
  secret: "e6e305fc8f1a82367f0c1de55ce8a886_this_is_the_secret_lol",
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'none',
    maxAge: null
  },
}));

app.use(bodyParser.urlencoded());
app.use(express.json());
app.use(cookieParser());
app.set('views', './views');
app.use('/static', express.static('./static'));

app.use(flash());

app.use(routes(db));


app.use(function(err, req, res, next) {
  console.log(err)
  res.status(500).json({ message: 'You broke me :(' });
});


(async() => {

  await db.connect();
  await db.migrate();
  
  httpsServer.listen(3443, () => {
    console.log(`Server running at https://${host}/`);
  });

})();


