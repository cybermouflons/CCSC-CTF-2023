const express = require('express')
const chatbot = require('../chatbot')
const isAuthenticated = require('../middleware/authentication');
const router = express.Router({ caseSensitive: true });

const response = data => ({ message: data });

const host = process.env.host

router.get('/', isAuthenticated, (req, res) => {
    return res.render('index.html', { host });
});

router.get('/login', (req, res) => {
    return res.render('login.html');
});

router.post('/login', async (req, res) => {
    const { username, password } = req.body;
  
    if (username && password) {

        return db.login(username, password)
            .then(user => {
                console.log(user);
                req.session.user_id = user.id;
                req.session.username = user.username;
                res.redirect('/');
            })
            .catch(() => res.status(403).send(response('Invalid username or password!')));
    }
    return res.status(500).send(response('Missing parameters!'));
    // If username and password are valid

});

router.get('/register', (req, res) => {
    return res.render('register.html');
});

router.post('/register', async (req, res) => {
    const { username, password } = req.body;

    user_exists = await db.user_exists(username);
    if(user_exists){
        console.log("User already exists") // Create flash message
        return res.status(500).send(response('Username already exists'));
    }

    await db.register(username,password);
  
    // Redirect to login page
    return res.redirect('/login');
  });

// app.get('/logout',(req,res) => {

//     req.session.destroy();

//     res.redirect('/');
// });

router.ws('/chat', function(ws, req) {
    ws.on('message', function(msg) {
      console.log(`Received message: ${msg}`);
      const response = chatbot(msg, req.session.user_id);
      ws.send(JSON.stringify(response));
    });

});

module.exports = database => {
    db = database;
    return router;
};