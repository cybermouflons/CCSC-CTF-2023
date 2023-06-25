const express = require("express");
const path = require("path");

const PORT = process.env.PORT || 8000;
const app = express();

var serialize = require('node-serialize');

app.use(express.static(path.join(__dirname, "build")));

app.get("/", function (req, res) {
  res.sendFile(path.join(__dirname, "build", "index.html"));
});

//vulnerable
app.get("/mission", (req, res) => {
  var message = serialize.unserialize(req.query.message);

  if (message){
  	res.json({ unserialized: message });
  }
  else{
  	res.json({ unserialized: "Please provide a mission message" });
  }
});

//Set the port that you want the server to run
app.listen(PORT, () => {
  console.log(`Server is listening on port ${PORT}`);
});
