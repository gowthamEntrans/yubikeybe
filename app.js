const express = require('express');
const session = require('express-session');
const u2f = require('u2f');
const cors = require('cors');

const app = express();
const APP_ID = 'https://yubikeyfe.vercel.app/'; // Replace with your HTTPS URL

app.use(express.json());
app.use(session({ secret: 'your-secret', resave: false, saveUninitialized: true }));
app.use(cors());

// Hardcoded user
const hardcodedUser = {
  username: 'g',
  password: '123', // Never hardcode passwords in production, use environment variables or secure storage
  keys: [],
};

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === hardcodedUser.username && password === hardcodedUser.password) {
    req.session.username = username;
    return res.sendStatus(200);
  }
  return res.sendStatus(401);
});

app.post('/registration-challenge', (req, res) => {
  if (!req.session.username) {
    return res.status(401).send('User not logged in');
  }

  const registrationRequest = u2f.request(APP_ID);
  req.session.registrationRequest = registrationRequest;
  return res.json(registrationRequest);
});

app.post('/registration-verify', (req, res) => {
  const result = u2f.checkRegistration(req.session.registrationRequest, req.body.registrationResponse);

  if (result.successful) {
    hardcodedUser.keys.push({
      publicKey: result.publicKey,
      keyHandle: result.keyHandle,
    });
    return res.sendStatus(200);
  }

  return res.status(400).json(result);
});

app.post('/authentication-challenge', (req, res) => {
  if (!req.session.username) {
    return res.status(401).send('User not logged in');
  }

  if (hardcodedUser.keys.length === 0) {
    return res.status(400).send('No registered keys found for user');
  }

  const keyHandles = hardcodedUser.keys.map(key => key.keyHandle);
  const authRequest = u2f.request(APP_ID, keyHandles);
  req.session.authRequest = authRequest;
  return res.json(authRequest);
});

app.post('/authentication-verify', (req, res) => {
  const key = hardcodedUser.keys.find(key => key.keyHandle === req.body.authResponse.keyHandle);
  if (!key) {
    return res.status(400).send('Key handle not found');
  }

  const result = u2f.checkSignature(req.session.authRequest, req.body.authResponse, key.publicKey);

  if (result.successful) {
    return res.sendStatus(200);
  }

  return res.status(400).json(result);
});

app.listen(3001, () => {
  console.log('Server running on port 3001');
});
