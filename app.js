var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var querystring = require('querystring');
var randomstring = require("randomstring");
var app = express();

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

var client = {
  id: 1,
  secret: "secure",
  scope: "profile email"
}

var userInfo = {
  id: 1337,
  firstName: "Max",
  lastName: "OAuth2.0User",
  email: "m.mustermann@example.com",
  age: 30
}

var userCredentials = {
  username: "m.mustermann@example.com",
  password: "maxssecret"
}

var tokens = []

// error handler
app.post('/token', (req, res, next) => {
  var auth = req.headers['authorization'];

  if (!auth) {
    console.log("no authorization header present")
    res.sendStatus(401);
    return;
  }

  var clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
  var clientId = querystring.unescape(clientCredentials[0]);
  var clientSecret = querystring.unescape(clientCredentials[1]);

  if (!(clientId == client.id && clientSecret == client.secret)) {
    console.log("invalid client credentials")
    res.sendStatus(401);
    return;
  }

  if (!req.body.grant_type === "password") {
    console.log("grant_type unsupported")
    res.sendStatus(401);
    return;
  }

  var username = req.body.username;
  var password = req.body.password;

  if (!(username && password)) {
    console.log("no usercredentials present")
    res.sendStatus(401);
    return;
  }

  if (!(username == userCredentials.username && password == userCredentials.password)) {
    console.log("invalid user credentials")
    res.sendStatus(401);
    return;
  }

  var actualScope = req.body.scope?.split(" ");
  var clientScope = client.scope.split(" ")

  if (!actualScope.every(scope => clientScope.includes(scope))) {
    console.log("invalid scope")
    res.sendStatus(401);
    return;
  }

  var accessToken = {
    content: randomstring.generate(12),
    sub: username
  };

  tokens.push(accessToken);

  console.log(accessToken)
  res.send({ token: accessToken.content });
});


app.get('/userinfo', (req, res, next) => {
  var auth = req.headers['authorization'];
  if (!auth?.startsWith("Bearer")) {
    console.log("invalid authorization header")
    res.sendStatus(401);
    return;
  }

  var splittedHeader = auth.split(" ")
  if (splittedHeader.length !== 2) {
    console.log(splittedHeader)
    console.log("invalid authorization header")
    res.sendStatus(401);
    return;
  }


  var foundToken = tokens.find(token => token.content === splittedHeader[1]);

  if (!foundToken) {
    console.log("invalid accesstoken")
    res.sendStatus(401);
    return;
  }

  if (foundToken.sub !== userInfo.email) {
    console.log("invalid accesstoken")
    res.sendStatus(401);
    return;
  }

  res.send(userInfo)
})

app.use(function (req, res, next) {
  next(createError(404));
});

module.exports = app;
